/**
Copyright 2022 IBM

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package permissions

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/operator-framework/operator-registry/alpha/action"
	"github.com/operator-framework/operator-registry/alpha/model"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sort"
	"strings"

	"github.com/IBM/operator-permission-advisor/pkg/duplicateHandler"
)

var (
	PermissionAdvisorNilError = errorAdvisorNil()
	SearchAccess              = duplicateHandler.New()
)

func errorAdvisorNil() error { return errors.New("cannot get permissions from a nil advisor") }

type PermissionAdvisorStruct struct {
	// PermissionAdvisorStruct holds information needed to inspect
	// a catalog source for permissions on a given Operator before an
	// OLM install

	// The catalog image reference pull location
	IndexReference string
	// The Operator package to inspect
	OperatorPackage string
	// The channel in the Operator package to inspect
	Channel string

	// Aggreagate is a flag to deteremine if we should get the permissions of
	// all bundles in a channel of just the head
	// When false, this means to just get the heads of channels permission info
	// when true, this means to aggregate permmissions across all bundles in the channel
	Aggregate bool
}

type PermissionAdvisor interface {
	GetPermissionsForAdvisor(context.Context) error
}

type permissionScope string

const (
	Namespace permissionScope = "namespace" // == role
	Cluster   permissionScope = "cluster"   // == clusterRole
)

type PermissionWrapper struct {
	// PermissionWrapper is our data contract that gives the
	// caller the information needed to create an aggregated
	// role or cluster role

	// The scope of the permission rule [cluster, namespace]
	Scope permissionScope
	// The rule definition for the permission policy
	Rule rbacv1.PolicyRule
}

// Hash returns a sha256 representation of the wrapper for map access
func (p *PermissionWrapper) Hash() string {
	/**
	 *
	 * We need to create a copy of each array so that
	 * the arrays can be sorted without changing the original
	 *
	 * Arrays need to be sorted because verbs: [get, create] and verbs: [create, get]
	 * are the same permission at the end of the day, so we need to
	 * normal the hash to account for this
	 *
	 */
	if p == nil {
		return "nil"
	}
	preHash := string(p.Scope) + "-"
	verbsCopy := p.Rule.Verbs[:]
	apiGroupsCopy := p.Rule.APIGroups[:]
	resourcesCopy := p.Rule.Resources[:]
	resourceNamesCopy := p.Rule.ResourceNames[:]
	nonResourceURLSCopy := p.Rule.NonResourceURLs[:]
	sort.Strings(verbsCopy)
	sort.Strings(apiGroupsCopy)
	sort.Strings(resourcesCopy)
	sort.Strings(resourceNamesCopy)
	sort.Strings(nonResourceURLSCopy)
	preHash += strings.Join(verbsCopy, "") + "-"
	preHash += strings.Join(apiGroupsCopy, "") + "-"
	preHash += strings.Join(resourcesCopy, "") + "-"
	preHash += strings.Join(resourceNamesCopy, "") + "-"
	preHash += strings.Join(nonResourceURLSCopy, "")
	h := sha256.New()
	h.Write([]byte(preHash))
	return string(h.Sum(nil))
}

// GetBundlesFromChannel will return an array of all bundles in the channel
// channel (*model.Channel): is the channel object request to get the bundles from
// returns ([]model.Bundle): an array of all bundles in the channel unless p.Aggregate is false,
//                           then will only return the bundle at the head of the channel
func (p *PermissionAdvisorStruct) GetBundlesFromChannel(channel *model.Channel) []model.Bundle {
	var bundles []model.Bundle
	if p == nil || channel == nil {
		return bundles
	}

	if !p.Aggregate {
		head, err := channel.Head()
		if err != nil {
			panic(err)
		}
		bundles = []model.Bundle{*head}
	} else {
		for _, bundle := range channel.Bundles {
			bundles = append(bundles, *bundle)
		}
	}

	return bundles
}

// GetChannelsForPackage will get all channels for a given pacakge in the listed package output
// packages ([]model.Package): is the list of all packages in the catalog index ref
//                             this is filtered based on the p.OperatorPackage field
// returns (map[string]*model.Channel): A map consisting of all channels by name for the filtered package
func (p *PermissionAdvisorStruct) GetChannelsForPackage(packages []model.Package) map[string]*model.Channel {
	// add a nil guard to the return here by initializing a memory address
	// for the map before returning it, even in a no-op case
	var channels map[string]*model.Channel = make(map[string]*model.Channel)
	if p == nil {
		return channels
	}

	// TODO: since the packages are in sorted array order by name, this can be
	//       optimized to use a binary search instead of brute force linear search
	//       I am using today to prove out the functionality.
	for _, packageName := range packages {
		if packageName.Name == p.OperatorPackage {
			return packageName.Channels
		}
	}

	return channels
}

// HeadOfChannelOrAggregateFromPackage is used to interface with the catalog image and opm APIs to return the bundle information containing the permissions
// ctx (context.Context): is the context to pass into the list command, usually inherited from the calling command
// returns ([]model.Bundle): an array of all bundles matching the given query parameters we want to aggregate permissions over
// returns (error): can come from a call to opm APIs, or if the permission advisor is nil
func (p *PermissionAdvisorStruct) HeadOfChannelOrAggregateFromPackage(ctx context.Context) ([]model.Bundle, error) {
	var allBundles []model.Bundle
	if p == nil {
		return allBundles, PermissionAdvisorNilError
	}
	// call out to the opm libraries to list the packages
	// and then filter this for the specified Operator package
	actionList := action.ListPackages{
		IndexReference: p.IndexReference,
	}

	// if there is an error in compiling the bundle action, we cannot continue
	// a common error scene is if C_GO or -tags json1 is not passed to the
	// go compiler and build time
	modelPackages, err := actionList.Run(ctx)
	if err != nil {
		return allBundles, err
	}

	channels := p.GetChannelsForPackage(modelPackages.Packages)
	var channel *model.Channel
	var ok bool
	if channel, ok = channels[p.Channel]; !ok {
		return allBundles, errors.New(fmt.Sprintf("the specified channel %q does not exist in the catalog reference", p.Channel))
	}

	allBundles = p.GetBundlesFromChannel(channel)

	return allBundles, nil
}

// GetPermissionsForAdvisor will return a list of permissions and their scopes found for the inputs
func (p *PermissionAdvisorStruct) GetPermissionsForAdvisor(ctx context.Context) ([]PermissionWrapper, error) {
	allPermissions := []PermissionWrapper{}

	if p == nil {
		return allPermissions, PermissionAdvisorNilError
	}

	bundles, err := p.HeadOfChannelOrAggregateFromPackage(ctx)
	if err != nil {
		return allPermissions, err
	}

	for _, bundle := range bundles {
		// trim the bundle objects from all possible kube manifests, to only the RBAC related ones
		permissionsManifests := filterObjectsInBundle(bundle.Objects)
		// permissions can exist in the manifests directory of the bundle and in the CSV
		// so we must aggregate the information between the two locations
		holderPermissions := append(getPermissionsFromUnstructuredArray(permissionsManifests), getPermissionsFromBundle(bundle)...)
		for _, p := range holderPermissions {
			if dupe := SearchAccess.CheckForDuplication(&p); !dupe {
				// Skip the error check in the return because the if already
				// ensures the hash does not exist in the map
				SearchAccess.RegisterDuplication(&p)
				allPermissions = append(allPermissions, p)
			}
		}
	}

	return allPermissions, nil
}

// getKindForObjectString internal util helper for getting the Kubernetes kind of a unstructured raw JSON string
// o (string) is a raw JSON string representing a Kubernetes manifest
func getKindForObjectString(o string) string {
	manifest := &unstructured.Unstructured{}
	if err := yaml.Unmarshal([]byte(o), manifest); err != nil {
		panic(err)
	}
	return manifest.GetKind()
}

// getPermissionsFromUnstructuredArray internal util for getting the permissions from the raw JSON text
// u ([]string) is an array of strings representing role or clusterRole raw JSON strings
func getPermissionsFromUnstructuredArray(u []string) []PermissionWrapper {
	permissions := []PermissionWrapper{}
	for _, manifest := range u {
		kind := getKindForObjectString(manifest)
		if strings.EqualFold(kind, "ClusterRole") {
			cr := &rbacv1.ClusterRole{}
			if err := yaml.Unmarshal([]byte(manifest), cr); err != nil {
				panic(err)
			}
			for _, r := range cr.Rules {
				permissions = append(permissions, PermissionWrapper{
					Scope: Cluster,
					Rule:  r,
				})
			}
		}
		if strings.EqualFold(kind, "Role") {
			r := &rbacv1.Role{}
			if err := yaml.Unmarshal([]byte(manifest), r); err != nil {
				panic(err)
			}
			for _, rRule := range r.Rules {
				permissions = append(permissions, PermissionWrapper{
					Scope: Namespace,
					Rule:  rRule,
				})
			}
		}
	}
	return permissions
}

// filterObjectsInBundle internal util for filtering out non-RBAC manifests in a bundle
// objects ([]string) is a list of all manifests in the bundle encoded as raw JSON texts
func filterObjectsInBundle(objects []string) []string {
	filtered := []string{}
	for _, obj := range objects {
		kind := getKindForObjectString(obj)
		if strings.EqualFold(kind, "ClusterRole") || strings.EqualFold(kind, "Role") {
			filtered = append(filtered, obj)
		}
	}
	return filtered
}

// getPermissionsFromBundle internal util for getting the CSV permissins from the bundle object
// b (model.Bundle) is the bundle object containing the CSV to extract permissions from
func getPermissionsFromBundle(b model.Bundle) []PermissionWrapper {
	rules := []PermissionWrapper{}
	csv := &v1alpha1.ClusterServiceVersion{}
	if err := yaml.Unmarshal([]byte(b.CsvJSON), csv); err != nil {
		panic(err)
	}
	clusterPermissions := csv.Spec.InstallStrategy.StrategySpec.ClusterPermissions
	permissions := csv.Spec.InstallStrategy.StrategySpec.Permissions

	for _, cp := range clusterPermissions {
		for _, r := range cp.Rules {
			rules = append(rules, PermissionWrapper{
				Scope: Cluster,
				Rule:  r,
			})
		}
	}

	for _, p := range permissions {
		for _, r := range p.Rules {
			rules = append(rules, PermissionWrapper{
				Scope: Namespace,
				Rule:  r,
			})
		}
	}

	return rules
}

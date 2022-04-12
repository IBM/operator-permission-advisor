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

package utils

import (
	"fmt"
	yaml "github.com/ghodss/yaml"
	"io/ioutil"
	rbacv1 "k8s.io/api/rbac/v1"

	"github.com/IBM/operator-permission-advisor/pkg/log"
)

type OutputWriter interface {
	Standard()
	Compact()
	ToFile() error
}

type PermissionsOutputWriter struct {
	// PermissionsOutputWriter is the wrapper type for the permissions API
	// to send data to the user front end

	// Roles is the array of role permissions to write to the user
	Roles *rbacv1.Role

	// ClusterRoles is the array of cluster role permissions to write to the user
	ClusterRoles *rbacv1.ClusterRole

	// Role is the file location for the role to be written to
	Role string

	// ClusterRole is the file location for the cluster role to be written to
	ClusterRole string

	internalRoleYAML        []byte
	internalClusterRoleYAML []byte
}

// Load will load data needed for later processing in the commands
func (w *PermissionsOutputWriter) Load() {
	if w == nil {
		return // no-op
	}
	w.internalRoleYAML, _ = yaml.Marshal(w.Roles)
	w.internalClusterRoleYAML, _ = yaml.Marshal(w.ClusterRoles)
}

// Standard will write the permission advisor data as the standard view
// to STDOUT file
func (w *PermissionsOutputWriter) Standard() {
	if w == nil {
		return // cannot write with a nil writer, this is a no-op
	}
	log.KLogger.Plain("Role:")
	log.KLogger.Plain(string(w.internalRoleYAML))
	log.KLogger.Plain("Cluster Role:")
	log.KLogger.Plain(string(w.internalClusterRoleYAML))
}

// Compact will write the permission advisor data as the compact view
// to STDOUT file
func (w *PermissionsOutputWriter) Compact() {
	if w == nil {
		return // cannot write with a nil writer, this is a no-op
	}

	log.KLogger.Plain(fmt.Sprintf("%s\n---\n%s\n", string(w.internalRoleYAML), string(w.internalClusterRoleYAML)))
}

// ToFile will write the permission advisor data role and cluster role
// to the specified files in the structure
// On error returns the file writing error returned from the OS package
func (w *PermissionsOutputWriter) ToFile() error {
	if w == nil {
		return nil // cannot write with a nil writer, this is a no-op
	}
	if w.Role != "" {
		if err := ioutil.WriteFile(w.Role, w.internalRoleYAML, 0644); err != nil {
			return err
		}
	}

	if w.ClusterRole != "" {
		if err := ioutil.WriteFile(w.ClusterRole, w.internalClusterRoleYAML, 0644); err != nil {
			return err
		}
	}

	return nil
}

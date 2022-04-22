package permissions

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/rand"
	"reflect"
	"sort"
	"testing"

	"github.com/google/uuid"
	"github.com/operator-framework/api/pkg/operators/v1alpha1"
	"github.com/operator-framework/operator-registry/alpha/model"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

/**
 *
- TODO: Move the helper functions to a testUtils package for use
        throughout the project
 *
 *
- TODO: Test_getPermissionsFromBundle and other tests of the same flavor
				should move the test data generation to a package that can randomize
				some of the test data.  Ideally we could specify a number of test sets to
				generate and get the expected / test set from the function and feed this
				into the unit test.  Currently there is some hardcoding and duplication
				that happens across the tests
 *
*/

func generateBundle(n string) *model.Bundle {
	return &model.Bundle{
		Name: n,
	}
}

func generateChannel(n string, p *model.Package, b []*model.Bundle) *model.Channel {
	bundleMap := make(map[string]*model.Bundle)
	for _, x := range b {
		bundleMap[x.Name] = x
	}

	return &model.Channel{
		Package: p,
		Name:    n,
		Bundles: bundleMap,
	}
}

func generatePackage(n string) *model.Package {
	return &model.Package{
		Name: n,
	}
}

func fixPackage(p *model.Package, cs []*model.Channel) {
	channelMap := make(map[string]*model.Channel)
	for _, c := range cs {
		channelMap[c.Name] = c
	}
	p.DefaultChannel = cs[0]
	p.Channels = channelMap
}

func getStringFromObj(i interface{}) string {
	tb, _ := json.Marshal(i)
	return string(tb)
}

func TestPermissionWrapper_Hash(t *testing.T) {
	type fields struct {
		Scope permissionScope
		Rule  rbacv1.PolicyRule
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "basic",
			fields: fields{
				Scope: Cluster,
				Rule: rbacv1.PolicyRule{
					Verbs:     []string{"use"},
					APIGroups: []string{"rbac.authorization.io"},
					Resources: []string{"role"},
				},
			},
			want: string(Cluster) + "-use" + "-rbac.authorization.io" + "-role" + "--",
		},
		{
			name: "duplicate",
			fields: fields{
				Scope: Cluster,
				Rule: rbacv1.PolicyRule{
					Verbs:     []string{"use", "get"},
					APIGroups: []string{"rbac.authorization.io"},
					Resources: []string{"role"},
				},
			},
			want: string(Cluster) + "-getuse" + "-rbac.authorization.io" + "-role" + "--",
		},
		{
			name: "duplicate more",
			fields: fields{
				Scope: Cluster,
				Rule: rbacv1.PolicyRule{
					Verbs:     []string{"use", "get"},
					APIGroups: []string{"rbac.authorization.io", "policy"},
					Resources: []string{"podSecurityPolicy", "role"},
				},
			},
			want: string(Cluster) + "-getuse" + "-policyrbac.authorization.io" + "-podSecurityPolicyrole" + "--",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PermissionWrapper{
				Scope: tt.fields.Scope,
				Rule:  tt.fields.Rule,
			}
			h := sha256.New()
			h.Write([]byte(tt.want))
			wantHash := string(h.Sum(nil))

			if got := p.Hash(); got != wantHash {
				t.Errorf("PermissionWrapper.Hash() = %v, want %v", got, wantHash)
			}
		})
	}
}

func TestPermissionAdvisorStruct_GetBundlesFromChannel(t *testing.T) {
	/*
		pseudo-randomly generate the test data to use in the later testing
	*/
	var bundleNames []string
	for i := 0; i < 10; i++ {
		bundleNames = append(bundleNames, fmt.Sprintf("bundle-%d", i))
	}
	var bundles []*model.Bundle
	for i := 0; i < 10; i++ {
		bundles = append(bundles, generateBundle(bundleNames[i]))
	}

	var channelNames []string
	for i := 0; i < 3; i++ {
		channelNames = append(channelNames, fmt.Sprintf("channel-%d", i))
	}
	var channels []*model.Channel

	packageName := "package"
	p := generatePackage(packageName)

	channelMap := make(map[string][]*model.Bundle)
	for _, bundle := range bundles {
		idx := rand.Intn(len(channelNames))
		channelMap[channelNames[idx]] = append(channelMap[channelNames[idx]], bundle)
	}

	for name, bundles := range channelMap {
		channels = append(channels, generateChannel(name, p, bundles))
	}

	fixPackage(p, channels)

	getChannelForName := func(s string) *model.Channel {
		for _, channel := range channels {
			if channel.Name == s {
				return channel
			}
		}
		return nil
	}

	wantDefault := func(bundles []*model.Bundle) []model.Bundle {
		var ret []model.Bundle
		for _, b := range bundles {
			ret = append(ret, *b)
		}
		return ret
	}

	type fields struct {
		IndexReference  string
		OperatorPackage string
		Channel         string
		Aggregate       bool
	}
	type args struct {
		channel *model.Channel
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   []model.Bundle
	}{
		{
			name: "default test",
			fields: fields{
				IndexReference:  "",
				OperatorPackage: "package",
				Channel:         channelNames[1],
				Aggregate:       true,
			},
			args: args{
				channel: getChannelForName(channelNames[1]),
			},
			want: wantDefault(channelMap[channelNames[1]]),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PermissionAdvisorStruct{
				IndexReference:  tt.fields.IndexReference,
				OperatorPackage: tt.fields.OperatorPackage,
				Channel:         tt.fields.Channel,
				Aggregate:       tt.fields.Aggregate,
			}
			got := p.GetBundlesFromChannel(tt.args.channel)
			sort.Slice(got, func(i int, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.Slice(tt.want, func(i int, j int) bool {
				return tt.want[i].Name < tt.want[j].Name
			})
			if !reflect.DeepEqual(got, tt.want) {
				for _, b := range got {
					fmt.Printf("Got -- %q\n", b.Name)
				}
				fmt.Println("--------")
				for _, b := range tt.want {
					fmt.Printf("Want -- %q\n", b.Name)
				}
				t.Errorf("PermissionAdvisorStruct.GetBundlesFromChannel() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermissionAdvisorStruct_GetChannelsForPackage(t *testing.T) {
	/*
		pseudo-randomly generate the test data to use in the later testing
	*/
	var channelNames []string
	for i := 0; i < 10; i++ {
		channelNames = append(channelNames, fmt.Sprintf("channel-%d", i))
	}
	var channels []*model.Channel

	var packageNames []string
	for i := 0; i < 3; i++ {
		packageNames = append(packageNames, fmt.Sprintf("package-%d", i))
	}
	var packages []*model.Package
	for i := 0; i < 3; i++ {
		packages = append(packages, generatePackage(packageNames[i]))
	}

	channelLen := len(channelNames) / 3

	for i := 0; i < 10; i++ {
		var idx int
		if i >= 0 || i < channelLen {
			idx = 0
		} else if i >= channelLen || i < 2*channelLen {
			idx = 1
		} else {
			idx = 2
		}

		channels = append(channels, generateChannel(channelNames[i], packages[idx], []*model.Bundle{}))
	}

	fixPackage(packages[0], channels[:channelLen])
	fixPackage(packages[1], channels[channelLen:2*channelLen])
	fixPackage(packages[2], channels[2*channelLen:])

	genPackagesFromPointers := func(ps []*model.Package) []model.Package {
		var ret []model.Package
		for _, p := range ps {
			ret = append(ret, *p)
		}
		return ret
	}

	genChannelMapFromPackage := func(p *model.Package) map[string]*model.Channel {
		ret := make(map[string]*model.Channel)
		for _, c := range p.Channels {
			ret[c.Name] = c
		}
		return ret
	}

	type fields struct {
		IndexReference  string
		OperatorPackage string
		Channel         string
		Aggregate       bool
	}
	type args struct {
		packages []model.Package
	}
	tests := []struct {
		name   string
		fields fields
		args   args
		want   map[string]*model.Channel
	}{
		{
			name: "default test",
			fields: fields{
				IndexReference:  "",
				OperatorPackage: packageNames[1],
				Channel:         channelNames[channelLen+1],
				Aggregate:       true,
			},
			args: args{
				packages: genPackagesFromPointers(packages),
			},
			want: genChannelMapFromPackage(packages[1]),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PermissionAdvisorStruct{
				IndexReference:  tt.fields.IndexReference,
				OperatorPackage: tt.fields.OperatorPackage,
				Channel:         tt.fields.Channel,
				Aggregate:       tt.fields.Aggregate,
			}
			if got := p.GetChannelsForPackage(tt.args.packages); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PermissionAdvisorStruct.GetChannelsForPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPermissionAdvisorStruct_HeadOfChannelOrAggregateFromPackage(t *testing.T) {
	type fields struct {
		IndexReference  string
		OperatorPackage string
		Channel         string
		Aggregate       bool
	}
	type args struct {
		ctx context.Context
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    []model.Bundle
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &PermissionAdvisorStruct{
				IndexReference:  tt.fields.IndexReference,
				OperatorPackage: tt.fields.OperatorPackage,
				Channel:         tt.fields.Channel,
				Aggregate:       tt.fields.Aggregate,
			}
			got, err := p.HeadOfChannelOrAggregateFromPackage(tt.args.ctx)
			if (err != nil) != tt.wantErr {
				t.Errorf("PermissionAdvisorStruct.HeadOfChannelOrAggregateFromPackage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("PermissionAdvisorStruct.HeadOfChannelOrAggregateFromPackage() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TODO: TestPermissionAdvisorStruct_GetPermissionsForAdvisor is currently commented out because it
// requires a test catalog to be published to pull and get permissions from.  Currently
// this catalog does not exist, and it would be good to setup a test image repo for this
// project to pull artifacts from used in testing.
//
// func TestPermissionAdvisorStruct_GetPermissionsForAdvisor(t *testing.T) {
// 	type fields struct {
// 		IndexReference  string
// 		OperatorPackage string
// 		Channel         string
// 		Aggregate       bool
// 	}
// 	type args struct {
// 		ctx context.Context
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want    []PermissionWrapper
// 		wantErr bool
// 	}{
// 		{
// 			name: "Test default",
// 			fields: fields{

// 			},
// 			args: args{

// 			},
// 			want []PermissionWrapper{},
// 			wantErro: false,
// 		}
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			p := &PermissionAdvisorStruct{
// 				IndexReference:  tt.fields.IndexReference,
// 				OperatorPackage: tt.fields.OperatorPackage,
// 				Channel:         tt.fields.Channel,
// 				Aggregate:       tt.fields.Aggregate,
// 			}
// 			got, err := p.GetPermissionsForAdvisor(tt.args.ctx)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("PermissionAdvisorStruct.GetPermissionsForAdvisor() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual(got, tt.want) {
// 				t.Errorf("PermissionAdvisorStruct.GetPermissionsForAdvisor() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }

func generateUnstructured(g, v, k, n string) *unstructured.Unstructured {
	u := &unstructured.Unstructured{}
	u.SetKind(k)
	u.SetName(n)
	u.SetAPIVersion(fmt.Sprintf("%s/%s", g, v))
	return u
}

func Test_getKindForObjectString(t *testing.T) {
	role := generateUnstructured("rbac.autherization.io", "v1", "Role", "test-role")
	clusterRole := generateUnstructured("rbac.autherization.io", "v1", "ClusterRole", "test-cluster-role")
	var roleb []byte
	var clusterRoleb []byte
	roleb, _ = json.Marshal(role)
	clusterRoleb, _ = json.Marshal(clusterRole)
	type args struct {
		o string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "test role",
			args: args{
				o: string(roleb),
			},
			want: role.GetKind(),
		},
		{
			name: "test clusteRole",
			args: args{
				o: string(clusterRoleb),
			},
			want: clusterRole.GetKind(),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getKindForObjectString(tt.args.o); got != tt.want {
				t.Errorf("getKindForObjectString() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPermissionsFromUnstructuredArray(t *testing.T) {
	roles := []*rbacv1.Role{
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Role",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:         []string{"use", "get"},
					APIGroups:     []string{"policy"},
					Resources:     []string{"podsecuritypolicy"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:         []string{"get", "use"},
					APIGroups:     []string{"policy"},
					Resources:     []string{"podsecuritypolicy"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"clusterrole"},
				},
			},
		},
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Role",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"clusterrole"},
				},
			},
		},
	}

	clusterRoles := []*rbacv1.ClusterRole{
		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRole",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:         []string{"use", "get"},
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployment"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:         []string{"get", "use"},
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployment"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"clusterrole"},
				},
			},
		},
		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRole",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"role"},
				},
			},
		},
	}

	generateUnstructuredBytesFromBytes := func(o []byte) []byte {
		u := &unstructured.Unstructured{}
		json.Unmarshal(o, u)
		tb, _ := json.Marshal(u)
		return tb
	}

	var testData []string
	var expected []PermissionWrapper
	for _, r := range roles {
		tb, _ := json.Marshal(r)
		testData = append(testData, string(generateUnstructuredBytesFromBytes(tb)))
		for _, rule := range r.Rules {
			expected = append(expected, PermissionWrapper{
				Scope: Namespace,
				Rule:  rule,
			})
		}
	}
	for _, cr := range clusterRoles {
		tb, _ := json.Marshal(cr)
		testData = append(testData, string(generateUnstructuredBytesFromBytes(tb)))
		for _, rule := range cr.Rules {
			expected = append(expected, PermissionWrapper{
				Scope: Cluster,
				Rule:  rule,
			})
		}
	}

	type args struct {
		u []string
	}
	tests := []struct {
		name string
		args args
		want []PermissionWrapper
	}{
		{
			name: "Test default",
			args: args{
				u: testData,
			},
			want: expected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPermissionsFromUnstructuredArray(tt.args.u)
			sort.Slice(got, func(i int, j int) bool {
				return got[i].Hash() < got[j].Hash()
			})

			sort.Slice(tt.want, func(i int, j int) bool {
				return tt.want[i].Hash() < tt.want[j].Hash()
			})

			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getPermissionsFromUnstructuredArray() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_filterObjectsInBundle(t *testing.T) {
	var testObjects []string
	var expected []string

	role := generateUnstructured("rbac.autherization.io", "v1", "Role", "test-role")
	clusterRole := generateUnstructured("rbac.autherization.io", "v1", "ClusterRole", "test-cluster-role")
	serviceaccount := generateUnstructured("", "v1", "ServiceAccount", "test-service-account")
	service := generateUnstructured("", "v1", "Service", "test-service")
	deployment := generateUnstructured("apps", "v1", "Deployment", "test-deployment")

	testObjects = []string{
		getStringFromObj(role),
		getStringFromObj(clusterRole),
		getStringFromObj(serviceaccount),
		getStringFromObj(service),
		getStringFromObj(deployment),
	}

	expected = []string{
		getStringFromObj(role),
		getStringFromObj(clusterRole),
	}

	type args struct {
		objects []string
	}
	tests := []struct {
		name string
		args args
		want []string
	}{
		{
			name: "test default",
			args: args{
				objects: testObjects,
			},
			want: expected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filterObjectsInBundle(tt.args.objects)
			sort.Strings(got)
			sort.Strings(tt.want)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("filterObjectsInBundle() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_getPermissionsFromBundle(t *testing.T) {
	roles := []*rbacv1.Role{
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Role",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:         []string{"use", "get"},
					APIGroups:     []string{"policy"},
					Resources:     []string{"podsecuritypolicy"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:         []string{"get", "use"},
					APIGroups:     []string{"policy"},
					Resources:     []string{"podsecuritypolicy"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"clusterrole"},
				},
			},
		},
		&rbacv1.Role{
			TypeMeta: metav1.TypeMeta{
				Kind:       "Role",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"clusterrole"},
				},
			},
		},
	}

	clusterRoles := []*rbacv1.ClusterRole{
		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRole",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:         []string{"use", "get"},
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployment"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:         []string{"get", "use"},
					APIGroups:     []string{"apps"},
					Resources:     []string{"deployment"},
					ResourceNames: []string{"restricted"},
				},
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"clusterrole"},
				},
			},
		},
		&rbacv1.ClusterRole{
			TypeMeta: metav1.TypeMeta{
				Kind:       "ClusterRole",
				APIVersion: "rbac.authorization.k8s.io/v1",
			},
			ObjectMeta: metav1.ObjectMeta{
				Name: uuid.New().String(),
			},
			Rules: []rbacv1.PolicyRule{
				rbacv1.PolicyRule{
					Verbs:     []string{"get", "use", "list", "watch"},
					APIGroups: []string{"rbac.autherization.io"},
					Resources: []string{"role"},
				},
			},
		},
	}

	testData := generateBundle("test-bundle")
	var csvPermissionsNamespace []rbacv1.PolicyRule
	var csvPermissionsCluster []rbacv1.PolicyRule

	for _, role := range roles {
		csvPermissionsNamespace = append(csvPermissionsNamespace, role.Rules...)
	}

	for _, role := range clusterRoles {
		csvPermissionsCluster = append(csvPermissionsCluster, role.Rules...)
	}

	csv := &v1alpha1.ClusterServiceVersion{
		TypeMeta: metav1.TypeMeta{
			Kind:       "ClusterServiceVersion",
			APIVersion: "operators.coreos.com/v1alpha1",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: uuid.New().String(),
		},
		Spec: v1alpha1.ClusterServiceVersionSpec{
			InstallStrategy: v1alpha1.NamedInstallStrategy{
				StrategySpec: v1alpha1.StrategyDetailsDeployment{
					Permissions: []v1alpha1.StrategyDeploymentPermissions{
						v1alpha1.StrategyDeploymentPermissions{
							ServiceAccountName: "test-sa",
							Rules:              csvPermissionsNamespace,
						},
					},
					ClusterPermissions: []v1alpha1.StrategyDeploymentPermissions{
						v1alpha1.StrategyDeploymentPermissions{
							ServiceAccountName: "test-sa",
							Rules:              csvPermissionsCluster,
						},
					},
				},
			},
		},
	}

	testData.CsvJSON = getStringFromObj(csv)

	var expected []PermissionWrapper
	for _, r := range roles {
		for _, rule := range r.Rules {
			expected = append(expected, PermissionWrapper{
				Scope: Namespace,
				Rule:  rule,
			})
		}
	}
	for _, cr := range clusterRoles {
		for _, rule := range cr.Rules {
			expected = append(expected, PermissionWrapper{
				Scope: Cluster,
				Rule:  rule,
			})
		}
	}
	type args struct {
		b model.Bundle
	}
	tests := []struct {
		name string
		args args
		want []PermissionWrapper
	}{
		{
			name: "Test default",
			args: args{
				b: *testData,
			},
			want: expected,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getPermissionsFromBundle(tt.args.b)
			sort.Slice(got, func(i, j int) bool {
				return got[i].Hash() < got[j].Hash()
			})
			sort.Slice(tt.want, func(i, j int) bool {
				return tt.want[i].Hash() < tt.want[j].Hash()
			})
			if !reflect.DeepEqual(got, tt.want) {
				for _, i := range got {
					fmt.Println(i)
				}
				fmt.Println("-----------")
				for _, i := range tt.want {
					fmt.Println(i)
				}
				t.Errorf("getPermissionsFromBundle() = %v, want %v", got, tt.want)
			}
		})
	}
}

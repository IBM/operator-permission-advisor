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

package cmd

import (
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"

	"github.com/IBM/operator-permission-advisor/pkg/log"
	opapermissions "github.com/IBM/operator-permission-advisor/pkg/permissions"
	"github.com/IBM/operator-permission-advisor/pkg/utils"
)

var (
	catalog         string
	channel         string
	operator        string
	roleFile        string
	clusterRoleFile string
	output          string
)

const (
	defaultFilePath string = "STDOUT"
	defaultOutput   string = "standard"
	compactOutput   string = "compact"
)

var (
	supportedOutputs       []string               = []string{defaultOutput, compactOutput}
	supportedOutputsSearch map[string]interface{} = make(map[string]interface{})
)

func init() {
	for _, supportedOutput := range supportedOutputs {
		supportedOutputsSearch[supportedOutput] = nil
	}
}

func verifyOutput(o string) bool {
	_, ok := supportedOutputsSearch[o]
	return ok
}

func lookupPermissionsCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "static",
		Short: "Statically check the catalog for permission information",
		Run: func(cmd *cobra.Command, args []string) {
			// log.KLogger.Info("catalog", catalog, "channel", channel, "operator", operator, "role", roleFile, "clusterRole", clusterRoleFile)

			if ok := verifyOutput(output); !ok {
				log.KLogger.Error(errors.New(fmt.Sprintf("the specified output flag value %q is not supported, please select one of %s", output, supportedOutputs)))
				os.Exit(1)
			}

			opa := &opapermissions.PermissionAdvisorStruct{
				IndexReference:  catalog,
				OperatorPackage: operator,
				Channel:         channel,
			}

			permissions, err := opa.GetPermissionsForAdvisor(cmd.Context())
			if err != nil {
				log.KLogger.Error(err)
				os.Exit(1)
			}

			rolePermissions := []rbacv1.PolicyRule{}
			clusterRolePermissions := []rbacv1.PolicyRule{}

			for _, permission := range permissions {
				if permission.Scope == opapermissions.Namespace {
					rolePermissions = append(rolePermissions, permission.Rule)
				}

				if permission.Scope == opapermissions.Cluster {
					clusterRolePermissions = append(clusterRolePermissions, permission.Rule)
				}
			}

			roleDef := &rbacv1.Role{
				TypeMeta: metav1.TypeMeta{
					Kind:       "Role",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: uuid.New().String(),
				},
				Rules: rolePermissions,
			}

			clusterRoleDef := &rbacv1.ClusterRole{
				TypeMeta: metav1.TypeMeta{
					Kind:       "ClusterRole",
					APIVersion: "rbac.authorization.k8s.io/v1",
				},
				ObjectMeta: metav1.ObjectMeta{
					Name: uuid.New().String(),
				},
				Rules: clusterRolePermissions,
			}

			var roleF, clusterRoleF string = roleFile, clusterRoleFile
			if roleF == defaultFilePath {
				roleF = ""
			}
			if clusterRoleF == defaultFilePath {
				clusterRoleF = ""
			}
			writer := &utils.PermissionsOutputWriter{
				Roles:        roleDef,
				ClusterRoles: clusterRoleDef,
				Role:         roleF,
				ClusterRole:  clusterRoleF,
			}

			writer.Load()
			switch output {
			case defaultOutput:
				writer.Standard()
			case compactOutput:
				writer.Compact()
			}
			if err := writer.ToFile(); err != nil {
				log.KLogger.Error(err)
				os.Exit(1)
			}
		},
	}

	cmd.Flags().StringVarP(&catalog, "catalog", "c", "", "catalog source image repo")
	cmd.Flags().StringVarP(&channel, "channel", "s", "", "channel to check for permissions in")
	cmd.Flags().StringVarP(&operator, "operator", "o", "", "operator package to check for permissions in")
	cmd.Flags().StringVarP(&roleFile, "role", "r", defaultFilePath, "location to save the aggregated role to")
	cmd.Flags().StringVarP(&clusterRoleFile, "clusterRole", "R", defaultFilePath, "location to save the aggregated clusterRole to")
	cmd.Flags().StringVarP(&output, "output", "k", defaultOutput, "toggle the STDOUT output format for scripting considerations")

	cmd.MarkFlagRequired("catalog")
	cmd.MarkFlagRequired("channel")
	cmd.MarkFlagRequired("operator")

	return cmd
}

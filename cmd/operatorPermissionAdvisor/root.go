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
	"github.com/spf13/cobra"
	"os"

	"github.com/IBM/operator-permission-advisor/pkg/log"
)

var configFile string
var commands []*cobra.Command = []*cobra.Command{}

var rootCmd = &cobra.Command{
	Use:   "operator-permission-advisor",
	Short: "Operator Permissions Advisor",
	Long:  "Operator Permissions Advisor is a CLI for getting an early preview look for the permissions an Operator channel will need for an install of the controller through an OLM install",
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		log.KLogger.Error(err)
		os.Exit(1)
	}
}

func registerCommand(cmd ...*cobra.Command) {
	commands = append(commands, cmd...)
}

func registerCommands() {
	for _, c := range commands {
		rootCmd.AddCommand(c)
	}
}

func init() {
	registerCommand(lookupPermissionsCommand())
	registerCommands()
}

# Operator Permission Advisor

[![Go Report](https://goreportcard.com/badge/github.com/nathanbrophy/operator-permission-advisor)](https://goreportcard.com/report/github.com/IBM/operator-permission-advisor)

Operator Permissions Advisor is a CLI tool that will take a catalog image and statically parse it to determine what permissions an Operator will request of OLM during an install.  The permissions are aggregated from the following sources:

1. The CSV
2. The `manifests` directory of each bundle in the desired install channel

This tool uses the standardized operator-registry `actions` library github.com/operator-framework/operator-registry/alpha/action to query the catalog.

## Usage

```
./operator-permission-advisor static --help
Statically check the catalog for permission information

Usage:
  operator-permission-advisor static [flags]

Flags:
  -c, --catalog string       catalog source image repo
  -s, --channel string       channel to check for permissions in
  -R, --clusterRole string   location to save the aggregated clusterRole to (default "STDOUT")
  -h, --help                 help for static
  -o, --operator string      operator package to check for permissions in
  -r, --role string          location to save the aggregated role to (default "STDOUT")
```

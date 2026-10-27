package main

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/Whiteknight07/meshscale/internal/exitnode"
)

func bugreportMeshRoutes(ctx context.Context) ([]byte, error) {
	snapshot, err := exitnode.Inspect(ctx, nil)
	if err != nil {
		return nil, err
	}
	tables := doctorWarpTables(snapshot)
	var output strings.Builder
	for _, family := range []string{"-4", "-6"} {
		for _, query := range bugreportRouteQueries(snapshot) {
			args := append([]string{"-j", family, "route", "show"}, strings.Fields(query)...)
			data, err := doctorCommand(ctx, "ip", args...)
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(&output, "%s %s:\n%s\n", family, query, data)
		}
	}
	return json.MarshalIndent(map[string]any{"warp_tables": tables, "ip_route": output.String()}, "", "  ")
}
func bugreportRouteQueries(snapshot exitnode.Snapshot) []string {
	queries := map[string]bool{}
	for table := range doctorWarpTables(snapshot) {
		if table == "main" || table == "254" || table == "<nil>" {
			queries["table main dev CloudflareWARP"] = true
		} else {
			queries["table "+table] = true
		}
	}
	for _, routes := range [][]exitnode.Route{snapshot.V4.Routes, snapshot.V6.Routes} {
		for _, route := range routes {
			if route.Dev != "meshsecure0" && route.Dev != "meshscale0" {
				continue
			}
			table := fmt.Sprint(route.Table)
			if route.Table == nil {
				table = "main"
			}
			// The main table is shared: include only Mesh interface routes from it.
			queries["table "+table+" dev "+route.Dev] = true
		}
	}
	result := make([]string, 0, len(queries))
	for query := range queries {
		result = append(result, query)
	}
	sort.Strings(result)
	return result
}

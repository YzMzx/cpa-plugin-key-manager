package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	"github.com/YzMzx/cpa-plugin-key/internal/usage"
)

const (
	FlagKeyUsage      = "key-usage"
	FlagKeyUsageKey   = "key-usage-key"
	FlagKeyUsageJSON  = "key-usage-json"
	FlagKeyUsageReset = "key-usage-reset"
)

// RegisterCLIFlags returns the CLI flags registered with CLIProxyAPI's `command_line.register`.
func RegisterCLIFlags() []pluginapi.CommandLineFlag {
	return []pluginapi.CommandLineFlag{
		{
			Name:         FlagKeyUsage,
			Type:         "bool",
			DefaultValue: "false",
			Usage:        "Print per-API-Key token usage and USD billing report from cpa-plugin-key and exit",
		},
		{
			Name:         FlagKeyUsageKey,
			Type:         "string",
			DefaultValue: "",
			Usage:        "Filter -key-usage report by a specific API Key",
		},
		{
			Name:         FlagKeyUsageJSON,
			Type:         "bool",
			DefaultValue: "false",
			Usage:        "Output -key-usage report in JSON format",
		},
		{
			Name:         FlagKeyUsageReset,
			Type:         "bool",
			DefaultValue: "false",
			Usage:        "Reset accumulated usage statistics (or only for -key-usage-key if specified) and exit",
		},
	}
}

// RenderUsageTable renders a human-readable ASCII table of per-API-Key and per-Model token usage & USD cost.
func RenderUsageTable(snap usage.PersistedSnapshot) string {
	var buf bytes.Buffer
	fmt.Fprintf(&buf, "====================================================================================================\n")
	fmt.Fprintf(&buf, " CLIProxyAPI Key Governance & Billing Report (Updated: %s)\n", snap.UpdatedAt)
	fmt.Fprintf(&buf, "====================================================================================================\n\n")

	if len(snap.Keys) == 0 {
		fmt.Fprintf(&buf, "No API Key usage records found.\n")
		return buf.String()
	}

	tw := tabwriter.NewWriter(&buf, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "API KEY\tNAME\tCONCURRENCY\tREQ(OK/ERR)\tINPUT\tOUTPUT\tCACHE(R/W)\tTOTAL TOKENS\tCOST (USD)")
	fmt.Fprintln(tw, "-------\t----\t-----------\t-----------\t-----\t------\t----------\t------------\t----------")

	keyIDs := usage.SortedKeyIDs(snap.Keys)
	var grandReq, grandIn, grandOut, grandRead, grandWrite, grandTotal, grandNano int64

	for _, k := range keyIDs {
		ks := snap.Keys[k]
		if ks == nil {
			continue
		}
		grandReq += ks.TotalRequests
		grandIn += ks.InputTokens
		grandOut += ks.OutputTokens
		grandRead += ks.CacheReadTokens
		grandWrite += ks.CacheWriteTokens
		grandTotal += ks.TotalTokens
		grandNano += ks.TotalCostNanoUSD

		concStr := fmt.Sprintf("%d/unlimited", ks.ActiveConcurrency)
		if ks.MaxConcurrency > 0 {
			concStr = fmt.Sprintf("%d/%d", ks.ActiveConcurrency, ks.MaxConcurrency)
		}
		name := ks.KeyName
		if name == "" {
			name = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d (%d/%d)\t%d\t%d\t%d/%d\t%d\t%s\n",
			ks.MaskedKey,
			name,
			concStr,
			ks.TotalRequests,
			ks.SuccessRequests,
			ks.FailedRequests,
			ks.InputTokens,
			ks.OutputTokens,
			ks.CacheReadTokens,
			ks.CacheWriteTokens,
			ks.TotalTokens,
			ks.TotalCostFormatted,
		)

		if len(ks.Models) > 0 {
			modelNames := make([]string, 0, len(ks.Models))
			for m := range ks.Models {
				modelNames = append(modelNames, m)
			}
			sort.Strings(modelNames)
			for _, m := range modelNames {
				ms := ks.Models[m]
				fmt.Fprintf(tw, "  └─ %s\t\t\t%d (%d/%d)\t%d\t%d\t%d/%d\t%d\t%s\n",
					ms.Model,
					ms.Requests,
					ms.SuccessRequests,
					ms.FailedRequests,
					ms.InputTokens,
					ms.OutputTokens,
					ms.CacheReadTokens,
					ms.CacheWriteTokens,
					ms.TotalTokens,
					ms.CostFormatted,
				)
			}
		}
	}
	_ = tw.Flush()

	fmt.Fprintf(&buf, "\n----------------------------------------------------------------------------------------------------\n")
	fmt.Fprintf(&buf, "GRAND TOTAL: Requests=%d | Input=%d | Output=%d | CacheRead=%d | CacheWrite=%d | TotalTokens=%d | TotalCost=$%.6f\n",
		grandReq, grandIn, grandOut, grandRead, grandWrite, grandTotal, float64(grandNano)/1e9)
	return buf.String()
}

// FormatUsageSnapshot formats a PersistedSnapshot as either JSON or ASCII table.
func FormatUsageSnapshot(snap usage.PersistedSnapshot, asJSON bool) (string, error) {
	if asJSON {
		raw, err := json.MarshalIndent(snap, "", "  ")
		if err != nil {
			return "", err
		}
		return string(raw) + "\n", nil
	}
	return RenderUsageTable(snap), nil
}

// ParseBoolFlag checks whether a flag value represents true.
func ParseBoolFlag(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	return s == "true" || s == "1" || s == "yes"
}

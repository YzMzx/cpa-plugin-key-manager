package authz

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
)

func TestRoundRobinUsesHighestMatchingPriorityTier(t *testing.T) {
	scheduler := NewScheduler()
	binding := UpstreamBinding{AuthIDs: []string{"*"}, Strategy: "round-robin"}
	request := pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{
		{ID: "low", Priority: 0}, {ID: "high-a", Priority: 10}, {ID: "middle", Priority: 5}, {ID: "high-b", Priority: 10},
	}}
	seen := map[string]int{}
	for i := 0; i < 20; i++ {
		response := scheduler.Pick("tenant", binding, request)
		if !response.Handled || response.Reject || (response.AuthID != "high-a" && response.AuthID != "high-b") {
			t.Fatalf("lower tier selected: %+v", response)
		}
		seen[response.AuthID]++
	}
	if seen["high-a"] != 10 || seen["high-b"] != 10 {
		t.Fatalf("best tier is not rotated evenly: %v", seen)
	}
}

func TestRoundRobinUsesLowerTierWhenItIsTheHighestBindingMatch(t *testing.T) {
	scheduler := NewScheduler()
	request := pluginapi.SchedulerPickRequest{Candidates: []pluginapi.SchedulerAuthCandidate{{ID: "shared-high", Priority: 10}, {ID: "tenant-low", Priority: -5}}}
	response := scheduler.Pick("tenant", UpstreamBinding{AuthIDs: []string{"tenant-low"}}, request)
	if !response.Handled || response.Reject || response.AuthID != "tenant-low" {
		t.Fatalf("bound lower tier rejected: %+v", response)
	}
	request.Candidates = []pluginapi.SchedulerAuthCandidate{{ID: "tenant-low-a", Priority: -5}, {ID: "tenant-low-b", Priority: -5}, {ID: "tenant-bottom", Priority: -10}}
	seen := map[string]int{}
	for i := 0; i < 10; i++ {
		response := scheduler.Pick("negative", UpstreamBinding{AuthIDs: []string{"tenant-*"}}, request)
		if response.AuthID == "tenant-bottom" || response.Reject {
			t.Fatalf("wrong negative priority tier: %+v", response)
		}
		seen[response.AuthID]++
	}
	if seen["tenant-low-a"] != 5 || seen["tenant-low-b"] != 5 {
		t.Fatalf("negative best tier is not rotated: %v", seen)
	}
}

package main

import "testing"

func TestNormalizeConnectorMAC(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "trim and lower", input: " AA:BB:CC:DD:EE:FF ", want: "aabbccddeeff"},
		{name: "dash separated", input: "AA-BB-CC-DD-EE-FF", want: "aabbccddeeff"},
		{name: "plain hex", input: "aabbccddeeff", want: "aabbccddeeff"},
	}

	for _, tc := range tests {
		if got := normalizeConnectorMAC(tc.input); got != tc.want {
			t.Fatalf("%s: expected %q, got %q", tc.name, tc.want, got)
		}
	}
}

func TestDeviceIDUsesCanonicalConnectorMAC(t *testing.T) {
	got := deviceID("AA:BB:CC:DD:EE:FF")
	want := "connector/aabbccddeeff"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestBlindDeviceFromResponseKeepsRawMACAndCanonicalExternalID(t *testing.T) {
	device := blindDeviceFromResponse(map[string]any{
		"mac":        "AA:BB:CC:DD:EE:FF",
		"deviceType": "02000001",
		"data": map[string]any{
			"type": 1,
		},
	}, "", "02000001", "192.168.1.50")

	if device.MAC != "AA:BB:CC:DD:EE:FF" {
		t.Fatalf("expected raw MAC to be preserved, got %q", device.MAC)
	}
	if device.ExternalID != "aabbccddeeff" {
		t.Fatalf("expected canonical external id, got %q", device.ExternalID)
	}
	if device.ID != "connector/aabbccddeeff" {
		t.Fatalf("expected canonical device id, got %q", device.ID)
	}
}

func TestDeviceStoreReplaceKeepsMissingDevicesOffline(t *testing.T) {
	store := newDeviceStore()
	store.devices["connector/aabbccddeeff"] = blindDevice{
		ID:         "connector/aabbccddeeff",
		MAC:        "AA:BB:CC:DD:EE:FF",
		ExternalID: "aabbccddeeff",
		Host:       "192.168.1.10",
		Name:       "Living room blind",
		Online:     true,
	}

	removed := store.replace(gatewayState{Host: "192.168.1.20", Available: true}, []blindDevice{})
	if len(removed) != 1 || removed[0] != "connector/aabbccddeeff" {
		t.Fatalf("expected removed list to contain the missing device id, got %#v", removed)
	}
	device, ok := store.get("connector/aabbccddeeff")
	if !ok {
		t.Fatal("expected missing device to remain in store as offline")
	}
	if device.Online {
		t.Fatal("expected missing device to be marked offline")
	}
	if device.Name != "Living room blind" {
		t.Fatalf("expected existing metadata to be preserved, got %q", device.Name)
	}
}

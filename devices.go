package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"
)

type Dev struct {
	IPv4       string
	IPv6       string
	MacAddress string
	Names      []string
}

type name struct {
	Name   string `json:"Name"`
	Source string `json:"Source"`
	Suffix string `json:"Suffix"`
	ID     string `json:"Id"`
}

// {"service":"Devices","method":"get","parameters":{"expression":{"ETHERNET":"not interface and not self and eth and .Active==true","WIFI":"not interface and not self and wifi and .Active==true"}}}
func getDevices(address, contextID string, cookie *http.Cookie) ([]Dev, error) {
	response, err := executeRequest(address, contextID, cookie, "Devices", "get", map[string]any{
		"expression": map[string]any{
			"ETHERNET": "not interface and not self and eth and .Active==true",
			"WIFI":     "not interface and not self and wifi and .Active==true",
		},
	})
	if err != nil {
		return nil, err
	}

	var data struct {
		Result struct {
			Status struct {
				Ethernet []struct {
					Key             string    `json:"Key"`
					DiscoverySource string    `json:"DiscoverySource"`
					Name            string    `json:"Name"`
					DeviceType      string    `json:"DeviceType"`
					Active          bool      `json:"Active"`
					Tags            string    `json:"Tags"`
					FirstSeen       time.Time `json:"FirstSeen"`
					LastConnection  time.Time `json:"LastConnection"`
					LastChanged     time.Time `json:"LastChanged"`
					Master          string    `json:"Master"`
					DeviceCategory  string    `json:"DeviceCategory"`
					VendorClassID   string    `json:"VendorClassID,omitempty"`
					UserClassID     string    `json:"UserClassID,omitempty"`
					ClientID        string    `json:"ClientID,omitempty"`
					SerialNumber    string    `json:"SerialNumber,omitempty"`
					ProductClass    string    `json:"ProductClass,omitempty"`
					Oui             string    `json:"OUI,omitempty"`
					DHCPOption55    string    `json:"DHCPOption55,omitempty"`
					IPAddress       string    `json:"IPAddress,omitempty"`
					IPAddressSource string    `json:"IPAddressSource,omitempty"`
					Location        string    `json:"Location"`
					PhysAddress     string    `json:"PhysAddress"`
					Layer2Interface string    `json:"Layer2Interface"`
					InterfaceName   string    `json:"InterfaceName"`
					MACVendor       string    `json:"MACVendor"`
					Owner           string    `json:"Owner"`
					UniqueID        string    `json:"UniqueID"`
					Index           string    `json:"Index"`
					Actions         []struct {
						Function  string `json:"Function"`
						Name      string `json:"Name"`
						Arguments []struct {
							Name      string `json:"Name"`
							Type      string `json:"Type"`
							Mandatory bool   `json:"Mandatory"`
						} `json:"Arguments,omitempty"`
					} `json:"Actions"`
					Names       []name `json:"Names"`
					DeviceTypes []struct {
						Type   string `json:"Type"`
						Source string `json:"Source"`
						ID     string `json:"Id"`
					} `json:"DeviceTypes"`
					Bdd struct {
						CloudVersion        string `json:"CloudVersion"`
						BDDRequestsSent     int    `json:"BDDRequestsSent"`
						BDDRequestsAnswered int    `json:"BDDRequestsAnswered"`
						BDDRequestsFailed   int    `json:"BDDRequestsFailed"`
						DeviceName          string `json:"DeviceName"`
						DeviceType          string `json:"DeviceType"`
						ModelName           string `json:"ModelName"`
						OperatingSystem     string `json:"OperatingSystem"`
						SoftwareVersion     string `json:"SoftwareVersion"`
						Manufacturer        string `json:"Manufacturer"`
						MACVendor           string `json:"MACVendor"`
						DeviceCategory      string `json:"DeviceCategory"`
					} `json:"BDD"`
					IPv4Address []struct {
						Address       string `json:"Address"`
						Status        string `json:"Status"`
						Scope         string `json:"Scope"`
						AddressSource string `json:"AddressSource"`
						Reserved      bool   `json:"Reserved"`
						ID            string `json:"Id"`
					} `json:"IPv4Address,omitempty"`
					IPv6Address []struct {
						Address       string `json:"Address"`
						Status        string `json:"Status"`
						Scope         string `json:"Scope"`
						AddressSource string `json:"AddressSource"`
						ID            string `json:"Id"`
					} `json:"IPv6Address,omitempty"`
					Locations   []any `json:"Locations"`
					MDNSService []any `json:"mDNSService,omitempty"`
					Groups      []any `json:"Groups"`
					Priority    struct {
						Configuration string `json:"Configuration"`
						Type          string `json:"Type"`
					} `json:"Priority"`
					UserAgents []any `json:"UserAgents"`
					WANAccess  struct {
						BlockedReasons string `json:"BlockedReasons"`
					} `json:"WANAccess"`
					SSWSta struct {
						SupportedStandards           string `json:"SupportedStandards"`
						Supports24GHz                bool   `json:"Supports24GHz"`
						Supports5GHz                 bool   `json:"Supports5GHz"`
						Supports6GHz                 bool   `json:"Supports6GHz"`
						ReconnectClass               string `json:"ReconnectClass"`
						FailedSteerCount             int    `json:"FailedSteerCount"`
						SuccessSteerCount            int    `json:"SuccessSteerCount"`
						AvgSteeringTime              int    `json:"AvgSteeringTime"`
						SupportedUNIIBands           string `json:"SupportedUNIIBands"`
						VendorSpecificElementOUIList string `json:"VendorSpecificElementOUIList"`
					} `json:"SSWSta,omitempty"`
					Version          string `json:"Version,omitempty"`
					DeviceID         int    `json:"DeviceId,omitempty"`
					AveragePhyTx     int    `json:"AveragePhyTx,omitempty"`
					AveragePhyRx     int    `json:"AveragePhyRx,omitempty"`
					User             string `json:"User,omitempty"`
					ModelName        string `json:"ModelName,omitempty"`
					OperatingSystem  string `json:"OperatingSystem,omitempty"`
					SoftwareVersion  string `json:"SoftwareVersion,omitempty"`
					Manufacturer     string `json:"Manufacturer,omitempty"`
					ModelNames       []any  `json:"ModelNames,omitempty"`
					OperatingSystems []any  `json:"OperatingSystems,omitempty"`
					SoftwareVersions []any  `json:"SoftwareVersions,omitempty"`
					Manufacturers    []struct {
						Source   string `json:"Source"`
						Value    string `json:"Value"`
						Priority int    `json:"Priority"`
						ID       string `json:"Id"`
					} `json:"Manufacturers,omitempty"`
				} `json:"ETHERNET"`
				Wifi []struct {
					Key                          string    `json:"Key"`
					DiscoverySource              string    `json:"DiscoverySource"`
					Name                         string    `json:"Name"`
					DeviceType                   string    `json:"DeviceType"`
					Active                       bool      `json:"Active"`
					Tags                         string    `json:"Tags"`
					FirstSeen                    time.Time `json:"FirstSeen"`
					LastConnection               time.Time `json:"LastConnection"`
					LastChanged                  time.Time `json:"LastChanged"`
					Master                       string    `json:"Master"`
					DeviceCategory               string    `json:"DeviceCategory"`
					VendorClassID                string    `json:"VendorClassID,omitempty"`
					UserClassID                  string    `json:"UserClassID,omitempty"`
					ClientID                     string    `json:"ClientID,omitempty"`
					SerialNumber                 string    `json:"SerialNumber,omitempty"`
					ProductClass                 string    `json:"ProductClass,omitempty"`
					Oui                          string    `json:"OUI,omitempty"`
					DHCPOption55                 string    `json:"DHCPOption55,omitempty"`
					IPAddress                    string    `json:"IPAddress,omitempty"`
					IPAddressSource              string    `json:"IPAddressSource,omitempty"`
					Location                     string    `json:"Location"`
					PhysAddress                  string    `json:"PhysAddress"`
					Layer2Interface              string    `json:"Layer2Interface"`
					InterfaceName                string    `json:"InterfaceName"`
					MACVendor                    string    `json:"MACVendor"`
					Owner                        string    `json:"Owner"`
					UniqueID                     string    `json:"UniqueID"`
					SignalStrength               int       `json:"SignalStrength"`
					SignalNoiseRatio             int       `json:"SignalNoiseRatio"`
					LastDataDownlinkRate         int       `json:"LastDataDownlinkRate"`
					LastDataUplinkRate           int       `json:"LastDataUplinkRate"`
					EncryptionMode               string    `json:"EncryptionMode"`
					LinkBandwidth                string    `json:"LinkBandwidth"`
					SecurityModeEnabled          string    `json:"SecurityModeEnabled"`
					HtCapabilities               string    `json:"HtCapabilities"`
					VhtCapabilities              string    `json:"VhtCapabilities"`
					HeCapabilities               string    `json:"HeCapabilities"`
					SupportedMCS                 string    `json:"SupportedMCS"`
					AuthenticationState          bool      `json:"AuthenticationState"`
					OperatingStandard            string    `json:"OperatingStandard"`
					OperatingFrequencyBand       string    `json:"OperatingFrequencyBand"`
					AvgSignalStrengthByChain     int       `json:"AvgSignalStrengthByChain"`
					MaxBandwidthSupported        string    `json:"MaxBandwidthSupported"`
					MaxDownlinkRateSupported     int       `json:"MaxDownlinkRateSupported"`
					MaxDownlinkRateReached       int       `json:"MaxDownlinkRateReached"`
					DownlinkMCS                  int       `json:"DownlinkMCS"`
					DownlinkBandwidth            int       `json:"DownlinkBandwidth"`
					DownlinkShortGuard           bool      `json:"DownlinkShortGuard"`
					UplinkMCS                    int       `json:"UplinkMCS"`
					UplinkBandwidth              int       `json:"UplinkBandwidth"`
					UplinkShortGuard             bool      `json:"UplinkShortGuard"`
					MaxUplinkRateSupported       int       `json:"MaxUplinkRateSupported"`
					MaxUplinkRateReached         int       `json:"MaxUplinkRateReached"`
					MaxTxSpatialStreamsSupported int       `json:"MaxTxSpatialStreamsSupported"`
					MaxRxSpatialStreamsSupported int       `json:"MaxRxSpatialStreamsSupported"`
					Index                        string    `json:"Index"`
					Actions                      []struct {
						Function  string `json:"Function"`
						Name      string `json:"Name"`
						Arguments []struct {
							Name      string `json:"Name"`
							Type      string `json:"Type"`
							Mandatory bool   `json:"Mandatory"`
						} `json:"Arguments,omitempty"`
					} `json:"Actions"`
					Names       []name `json:"Names"`
					DeviceTypes []struct {
						Type   string `json:"Type"`
						Source string `json:"Source"`
						ID     string `json:"Id"`
					} `json:"DeviceTypes"`
					Bdd struct {
						CloudVersion        string `json:"CloudVersion"`
						BDDRequestsSent     int    `json:"BDDRequestsSent"`
						BDDRequestsAnswered int    `json:"BDDRequestsAnswered"`
						BDDRequestsFailed   int    `json:"BDDRequestsFailed"`
						DeviceName          string `json:"DeviceName"`
						DeviceType          string `json:"DeviceType"`
						ModelName           string `json:"ModelName"`
						OperatingSystem     string `json:"OperatingSystem"`
						SoftwareVersion     string `json:"SoftwareVersion"`
						Manufacturer        string `json:"Manufacturer"`
						MACVendor           string `json:"MACVendor"`
						DeviceCategory      string `json:"DeviceCategory"`
					} `json:"BDD"`
					IPv4Address []struct {
						Address       string `json:"Address"`
						Status        string `json:"Status"`
						Scope         string `json:"Scope"`
						AddressSource string `json:"AddressSource"`
						Reserved      bool   `json:"Reserved"`
						ID            string `json:"Id"`
					} `json:"IPv4Address,omitempty"`
					IPv6Address []any `json:"IPv6Address,omitempty"`
					Locations   []any `json:"Locations"`
					Groups      []any `json:"Groups"`
					Priority    struct {
						Configuration string `json:"Configuration"`
						Type          string `json:"Type"`
					} `json:"Priority"`
					SSWSta struct {
						SupportedStandards           string `json:"SupportedStandards"`
						Supports24GHz                bool   `json:"Supports24GHz"`
						Supports5GHz                 bool   `json:"Supports5GHz"`
						Supports6GHz                 bool   `json:"Supports6GHz"`
						ReconnectClass               string `json:"ReconnectClass"`
						FailedSteerCount             int    `json:"FailedSteerCount"`
						SuccessSteerCount            int    `json:"SuccessSteerCount"`
						AvgSteeringTime              int    `json:"AvgSteeringTime"`
						SupportedUNIIBands           string `json:"SupportedUNIIBands"`
						VendorSpecificElementOUIList string `json:"VendorSpecificElementOUIList"`
					} `json:"SSWSta"`
					UserAgents []any `json:"UserAgents"`
					WANAccess  struct {
						BlockedReasons string `json:"BlockedReasons"`
					} `json:"WANAccess"`
					MDNSService []any `json:"mDNSService,omitempty"`
					Lltd        struct {
						ManagementURL          string `json:"ManagementURL"`
						PhysicalMedium         int    `json:"PhysicalMedium"`
						WirelessMode           int    `json:"WirelessMode"`
						Bssid                  string `json:"BSSID"`
						Ssid                   string `json:"SSID"`
						WirelessPhysicalMedium int    `json:"WirelessPhysicalMedium"`
						MaxRate                int    `json:"MaxRate"`
						LinkSpeed              int    `json:"LinkSpeed"`
						Rssi                   int    `json:"RSSI"`
						Support                string `json:"Support"`
					} `json:"LLTD,omitempty"`
				} `json:"WIFI"`
			} `json:"status"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(response), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	var devices []Dev
	for _, device := range data.Result.Status.Ethernet {
		devices = append(devices, Dev{
			IPv4:       device.IPAddress,
			MacAddress: device.PhysAddress,
			Names:      extractNames(device.Names),
		})
	}
	for _, device := range data.Result.Status.Wifi {
		devices = append(devices, Dev{
			IPv4:       device.IPAddress,
			MacAddress: device.PhysAddress,
			Names:      extractNames(device.Names),
		})
	}
	return devices, nil
}

func extractNames(names []name) []string {
	var result []string
	fmt.Println("Names:", names)
	for _, name := range names {
		if name.Name == "Device" {
			continue
		}
		result = append(result, name.Name)
	}

	// For some reason, the names are not unique. Let's remove duplicates.
	result = slices.Compact(result)

	return result
}

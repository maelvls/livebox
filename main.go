package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/goccy/go-yaml"
	"github.com/maelvls/undent"
	"github.com/spf13/cobra"
)

var (
	liveboxAddress  string
	liveboxUsername string
	liveboxPassword string
	debug           bool
)

type Config struct {
	Address  string `yaml:"address"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func loadConfig() (Config, error) {
	config := Config{
		Address:  "192.168.1.1",
		Username: "admin",
	}

	configPath := os.Getenv("HOME") + "/.config/livebox.yml"
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return config, nil // Use default config if file doesn't exist
	}

	configFile, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("failed to read config file: %w", err)
	}

	err = yaml.Unmarshal(configFile, &config)
	if err != nil {
		return config, fmt.Errorf("failed to unmarshal config file: %w", err)
	}

	return config, nil
}

func saveConfig(config Config) error {
	configPath := os.Getenv("HOME") + "/.config/livebox.yml"
	configFile, err := yaml.Marshal(config)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	err = os.WriteFile(configPath, configFile, 0600)
	if err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}

	return nil
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "livebox",
		Short: "A CLI for interacting with a Livebox 4 or 5 (Orange)",

		// SilenceUsage prevents Cobra from displaying the command's and
		// subcommands' usage on errors. Most of the errors have nothing to do
		// with the usage of the flags, and it is more confusing than helpful.
		// In case of an issue the flags, the user will still see an helpful
		// error message, and they can use --help to get the usage information.
		// See: https://github.com/spf13/cobra/issues/340#issuecomment-243790200
		SilenceUsage: true,

		// SilenceErrors prevents Cobra from logging the error returned from the
		// subcommands' RunE functions since we want to log the error ourselves
		// once Execute returns.
		SilenceErrors: true,
	}

	rootCmd.PersistentFlags().StringVar(&liveboxAddress, "address", "", "IP or hostname of the livebox")
	rootCmd.PersistentFlags().StringVar(&liveboxUsername, "username", "", "Username to use for authentication")
	rootCmd.PersistentFlags().StringVar(&liveboxPassword, "password", "", "Password to use for authentication")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")

	rootCmd.AddCommand(
		loginCmd(),
		lsCmd(),
		rebootCmd(),
		phoneCmd(),
		speedCmd(),
		portForwardCmd(),
		pinholeCmd(),
		apiCmd(),
		staticLeaseCmd(),
		dmzCmd(),
		wifiCmd(),
		dnsCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}

func authenticate(address, username, password string) (contextID string, sessid *http.Cookie, _ error) {
	authURL := fmt.Sprintf("http://%s/ws", address)
	payloadBytes, err := json.Marshal(map[string]any{
		"service": "sah.Device.Information",
		"method":  "createContext",
		"parameters": map[string]any{
			"applicationName": "webui",
			"username":        username,
			"password":        password,
		},
	})
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal auth payload: %w", err)
	}

	req, err := http.NewRequest("POST", authURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", nil, fmt.Errorf("failed to create auth request: %w", err)
	}

	req.Header.Set("Authorization", "X-Sah-Login")
	req.Header.Set("Content-Type", "application/x-sah-ws-4-call+json")

	// Execute the request
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", nil, fmt.Errorf("failed to execute auth request: %w", err)
	}
	defer resp.Body.Close()

	// Read the response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", nil, fmt.Errorf("failed to read auth response body: %w", err)
	}

	var result struct {
		Status int `json:"status"`
		Data   struct {
			ContextID string `json:"contextID"`
		} `json:"data"`
	}
	err = json.Unmarshal(bodyBytes, &result)
	if err != nil {
		return "", nil, fmt.Errorf("while parsing the auth response '%s': %w", string(bodyBytes), err)
	}

	if result.Status != 0 {
		return "", nil, fmt.Errorf("authentication failed: status %d, body: %s", result.Status, string(bodyBytes))
	}

	// Parse the Set-Cookie header to extract the sessid cookie.
	sessid, err = parseCookie(resp.Header.Get("Set-Cookie"))
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse cookie: %w", err)
	}

	return result.Data.ContextID, sessid, nil
}

// You can get the err info using:
//
//	var apiErrs APIErrors
//	errors.As(err, &apiErrs)
func executeRequest(address, contextID string, cookie *http.Cookie, service, method string, parameters map[string]any) (string, error) {
	requestURL := fmt.Sprintf("http://%s/ws", address)

	payload := map[string]any{
		"service":    service,
		"method":     method,
		"parameters": parameters,
	}
	payloadBytes, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(payloadBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Authorization", "X-Sah "+contextID)
	req.Header.Set("Content-Type", "application/x-sah-ws-1-call+json")
	req.AddCookie(cookie)
	req.AddCookie(&http.Cookie{Name: "sah/contextId", Value: contextID})
	req.Header.Set("X-Context", contextID)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Example error response:
	// 	{"result":{"status":null,"errors":[{"error":13,"description":"Permission denied","info":"TopologyDiagnostics"}]}}
	//  {"result":{"status":null,"errors":[{"error":196640,"description":"Missing mandatory argument","info":"origin"},{"error":196640,"description":"Missing mandatory argument","info":"sourceInterface"},{"error":196640,"description":"Missing mandatory argument","info":"internalPort"},{"error":196640,"description":"Missing mandatory argument","info":"destinationIPAddress"},{"error":196640,"description":"Missing mandatory argument","info":"protocol"}]}}
	var result struct {
		Result struct {
			Status any       `json:"status"`
			Errors APIErrors `json:"errors"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(bodyBytes), &result)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal result: %w", err)
	}
	if len(result.Result.Errors) > 0 {
		var errs []string
		for _, err := range result.Result.Errors {
			errs = append(errs, fmt.Sprintf("  * %d: %s: %s", err.ErrorCode, err.Description, err.Info))
		}
		return "", fmt.Errorf("while running method '%s' on service %s:\n%w", method, service, APIErrors(result.Result.Errors))
	}

	return string(bodyBytes), nil
}

type APIErrors []APIError

func (e APIErrors) Error() string {
	var errs []string
	for _, err := range e {
		errs = append(errs, fmt.Sprintf("  * %d: %s: %s", err.ErrorCode, err.Description, err.Info))
	}
	return strings.Join(errs, "\n")
}

func (e APIErrors) GetCode(code int) (APIError, bool) {
	for _, err := range e {
		if err.ErrorCode == code {
			return err, true
		}
	}
	return APIError{}, false
}

type APIError struct {
	ErrorCode   int    `json:"error"`
	Description string `json:"description"`
	Info        string `json:"info"`
}

func (e APIError) Error() string {
	return fmt.Sprintf("%d: %s: %s", e.ErrorCode, e.Description, e.Info)
}

func loginCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Authenticate to the livebox and save the information",
		RunE: func(cmd *cobra.Command, args []string) error {

			config, err := loadConfig()
			if err != nil {
				return err
			}

			var fields []huh.Field

			// Load the current configuration and prompt the user for new
			// values.
			c, err := loadConfig()
			if err != nil {
				return fmt.Errorf("failed to load configuration: %w", err)
			}

			// Let's let the user know if the username and password already
			// work.
			_, _, err = authenticate(c.Address, c.Username, c.Password)
			if err == nil {
				fields = append(fields, huh.NewNote().
					Title("🎉 Your credentials are already working. You can still update them if you want."),
				)
			}

			fields = append(fields,
				huh.NewInput().
					Title("Livebox Address").
					Value(&c.Address).
					Placeholder(config.Address).
					Description("Enter the hostname or IP of the Livebox."),
				huh.NewInput().
					Title("Username").
					Value(&c.Username).
					Placeholder(config.Username).
					Description("Enter the username."),
				huh.NewInput().
					Title("Password").
					EchoMode(huh.EchoModePassword).
					Value(&c.Password).
					Description("Enter the password. By default, it is the 8 first chars of the Wi-Fi passcode."),
			)

			form := huh.NewForm(huh.NewGroup(fields...))
			err = form.Run()
			if err != nil {
				return fmt.Errorf("form failed: %w", err)
			}

			// Check that the new config works.
			_, _, err = authenticate(c.Address, c.Username, c.Password)
			if err != nil {
				return fmt.Errorf("failed to authenticate with new configuration: %w", err)
			}

			err = saveConfig(c)
			if err != nil {
				return err
			}

			fmt.Println("Configuration saved in ~/.config/livebox.yml.")
			return nil
		},
	}
}

func lsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all devices known and their IPs",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			response, err := executeRequest(address, contextID, cookie, "TopologyDiagnostics", "buildTopology", map[string]any{"SendXmlFile": false})
			if err != nil {
				return err
			}

			// Extract the devices from the response.
			var data struct {
				Result struct {
					Status []struct {
						LastUpdate            time.Time `json:"LastUpdate"`
						DiagnosticMode        string    `json:"DiagnosticMode"`
						APIVersion            string    `json:"APIVersion"`
						Key                   string    `json:"Key"`
						DiscoverySource       string    `json:"DiscoverySource"`
						Name                  string    `json:"Name"`
						DeviceType            string    `json:"DeviceType"`
						Active                bool      `json:"Active"`
						Tags                  string    `json:"Tags"`
						FirstSeen             time.Time `json:"FirstSeen"`
						LastConnection        time.Time `json:"LastConnection"`
						LastChanged           time.Time `json:"LastChanged"`
						Master                string    `json:"Master"`
						Location              string    `json:"Location"`
						Owner                 string    `json:"Owner"`
						Manufacturer          string    `json:"Manufacturer"`
						ModelName             string    `json:"ModelName"`
						Description           string    `json:"Description"`
						SerialNumber          string    `json:"SerialNumber"`
						ProductClass          string    `json:"ProductClass"`
						HardwareVersion       string    `json:"HardwareVersion"`
						SoftwareVersion       string    `json:"SoftwareVersion"`
						BootLoaderVersion     string    `json:"BootLoaderVersion"`
						FirewallLevel         string    `json:"FirewallLevel"`
						LinkType              string    `json:"LinkType"`
						LinkState             string    `json:"LinkState"`
						ConnectionProtocol    string    `json:"ConnectionProtocol"`
						ConnectionState       string    `json:"ConnectionState"`
						LastConnectionError   string    `json:"LastConnectionError"`
						ConnectionIPv4Address string    `json:"ConnectionIPv4Address"`
						ConnectionIPv6Address string    `json:"ConnectionIPv6Address"`
						RemoteGateway         string    `json:"RemoteGateway"`
						DNSServers            string    `json:"DNSServers"`
						Internet              bool      `json:"Internet"`
						Iptv                  bool      `json:"IPTV"`
						Telephony             bool      `json:"Telephony"`
						DownstreamCurrRate    int       `json:"DownstreamCurrRate"`
						UpstreamCurrRate      int       `json:"UpstreamCurrRate"`
						DownstreamMaxBitRate  int       `json:"DownstreamMaxBitRate"`
						UpstreamMaxBitRate    int       `json:"UpstreamMaxBitRate"`
						Index                 string    `json:"Index"`
						Alternative           []string  `json:"Alternative"`
						Locations             []any     `json:"Locations"`
						Groups                []any     `json:"Groups"`
						Ssw                   struct {
							Capabilities string `json:"Capabilities"`
							CurrentMode  string `json:"CurrentMode"`
						} `json:"SSW"`
						Names []struct {
							Name   string `json:"Name"`
							Source string `json:"Source"`
							Suffix string `json:"Suffix"`
							ID     string `json:"Id"`
						} `json:"Names"`
						DeviceTypes []struct {
							Type   string `json:"Type"`
							Source string `json:"Source"`
							ID     string `json:"Id"`
						} `json:"DeviceTypes"`
						Children []Child `json:"Children"`
					} `json:"status"`
				} `json:"result"`
			}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}
			if len(data.Result.Status) == 0 {
				return fmt.Errorf("response does not contain the result.status field")
			}

			devices := flatten(data.Result.Status[0].Children)

			var rows [][]string
			for _, device := range devices {
				if device.IPAddress == "" {
					continue
				}
				rows = append(rows, []string{device.Name, device.IPAddress, device.PhysAddress})
			}
			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("Name", "IP Address", "MAC Address").
				Rows(rows...)

			fmt.Println(t.String())

			return nil
		},
	}
}

func flatten(children []Child) []Child {
	var devices []Child
	for _, child := range children {
		child := child
		devices = append(devices, flatten(child.Children)...)
		child.Children = nil
		devices = append(devices, child)
	}
	return devices
}

// Example of a device:
//
//  {
//  	"Key": "0A:7D:5C:93:78:5A",
//  	"DiscoverySource": "import",
//  	"Name": "MacBookPro-1",
//  	"DeviceType": "Computer",
//  	"Active": false,
//  	"Tags": "lan edev mac physical flowstats ipv4 ipv6 dhcp ssw_sta events wifi",
//  	"FirstSeen": "2025-01-16T02:02:04Z",
//  	"LastConnection": "2025-02-05T07:02:11Z",
//  	"LastChanged": "2025-02-05T07:03:10Z",
//  	"Master": "",
//  	"DeviceCategory": "",
//  	"VendorClassID": "",
//  	"UserClassID": "",
//  	"ClientID": "01:0A:7D:5C:93:78:5A",
//  	"SerialNumber": "",
//  	"ProductClass": "",
//  	"OUI": "",
//  	"DHCPOption55": "[1,121,3,6,15,108,114,119,252,95,44,46]",
//  	"IPAddress": "",
//  	"IPAddressSource": "",
//  	"Location": "",
//  	"PhysAddress": "0A:7D:5C:93:78:5A",
//  	"Layer2Interface": "wl0",
//  	"InterfaceName": "wl0",
//  	"MACVendor": "",
//  	"Owner": "",
//  	"UniqueID": "urn:uuid:8dd9b8ec-0b28-4570-9d98-ea1292e0cf91",
//  	"SignalStrength": -75,
//  	"SignalNoiseRatio": 16,
//  	"LastDataDownlinkRate": 5500,
//  	"LastDataUplinkRate": 5500,
//  	"EncryptionMode": "Default",
//  	"LinkBandwidth": "Unknown",
//  	"SecurityModeEnabled": "None",
//  	"HtCapabilities": "",
//  	"VhtCapabilities": "",
//  	"HeCapabilities": "",
//  	"SupportedMCS": "",
//  	"AuthenticationState": true,
//  	"OperatingStandard": "n",
//  	"OperatingFrequencyBand": "2.4GHz",
//  	"AvgSignalStrengthByChain": -76,
//  	"MaxBandwidthSupported": "20MHz",
//  	"MaxDownlinkRateSupported": 0,
//  	"MaxDownlinkRateReached": 117000,
//  	"DownlinkMCS": 0,
//  	"DownlinkBandwidth": 0,
//  	"DownlinkShortGuard": false,
//  	"UplinkMCS": 0,
//  	"UplinkBandwidth": 0,
//  	"UplinkShortGuard": false,
//  	"MaxUplinkRateSupported": 0,
//  	"MaxUplinkRateReached": 11000,
//  	"MaxTxSpatialStreamsSupported": 0,
//  	"MaxRxSpatialStreamsSupported": 0,
//  	"Index": "44",
//  	"Names": [
//  		{
//  		"Name": "Device",
//  		"Source": "default",
//  		"Suffix": "44",
//  		"Id": "default"
//  		},
//  		{
//  		"Name": "MacBookPro",
//  		"Source": "dhcp",
//  		"Suffix": "1",
//  		"Id": "dhcp"
//  		}
//  	],
//  	"DeviceTypes": [
//  		{
//  		"Type": "Computer",
//  		"Source": "default",
//  		"Id": "default"
//  		}
//  	],
//  	"BDD": {
//  		"CloudVersion": "",
//  		"BDDRequestsSent": 0,
//  		"BDDRequestsAnswered": 0,
//  		"BDDRequestsFailed": 0,
//  		"DeviceName": "",
//  		"DeviceType": "",
//  		"ModelName": "",
//  		"OperatingSystem": "",
//  		"SoftwareVersion": "",
//  		"Manufacturer": "",
//  		"MACVendor": "",
//  		"DeviceCategory": ""
//  	},
//  	"IPv4Address": [],
//  	"IPv6Address": [],
//  	"Locations": [],
//  	"Groups": [],
//  	"Priority": {
//  		"Configuration": "All",
//  		"Type": "BestEffort"
//  	},
//  	"SSWSta": {
//  		"SupportedStandards": "",
//  		"Supports24GHz": true,
//  		"Supports5GHz": true,
//  		"Supports6GHz": false,
//  		"ReconnectClass": "",
//  		"FailedSteerCount": 0,
//  		"SuccessSteerCount": 0,
//  		"AvgSteeringTime": 0,
//  		"SupportedUNIIBands": "U-NII-1,U-NII-2C",
//  		"VendorSpecificElementOUIList": "00:00:00"
//  	},
//  	"UserAgents": [],
//  	"WANAccess": { "BlockedReasons": "" },
//  	"InterfaceType": "Wi-Fi"
//  }

type Child struct {
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
	BusName         string    `json:"BusName,omitempty"`
	Index           string    `json:"Index"`
	Names           []struct {
		Name   string `json:"Name"`
		Source string `json:"Source"`
		Suffix string `json:"Suffix"`
		ID     string `json:"Id"`
	} `json:"Names"`
	DeviceTypes            []any   `json:"DeviceTypes"`
	Children               []Child `json:"Children,omitempty"`
	PortState              string  `json:"PortState,omitempty"`       // "Connected"
	PhysAddress            string  `json:"PhysAddress,omitempty"`     // "0A:7D:5C:93:78:5A"
	Layer2Interface        string  `json:"Layer2Interface,omitempty"` // "wl0"
	InterfaceName          string  `json:"InterfaceName,omitempty"`   // "wl0"
	MACVendor              string  `json:"MACVendor,omitempty"`       // Always empty.
	NetDevName             string  `json:"NetDevName,omitempty"`
	NetDevIndex            int     `json:"NetDevIndex,omitempty"`
	IPAddress              string  `json:"IPAddress,omitempty"`
	IPAddressSource        string  `json:"IPAddressSource,omitempty"`
	DHCPv4ServerPool       string  `json:"DHCPv4ServerPool,omitempty"`
	DHCPv4ServerEnable     bool    `json:"DHCPv4ServerEnable,omitempty"`
	DHCPv4ServerMinAddress string  `json:"DHCPv4ServerMinAddress,omitempty"`
	DHCPv4ServerMaxAddress string  `json:"DHCPv4ServerMaxAddress,omitempty"`
	DHCPv4ServerNetmask    string  `json:"DHCPv4ServerNetmask,omitempty"`
	DHCPv4DomainName       string  `json:"DHCPv4DomainName,omitempty"`
	IPv4Address            []struct {
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
	Location  string `json:"Location,omitempty"`
	Owner     string `json:"Owner,omitempty"`
	Locations []any  `json:"Locations,omitempty"`
	Groups    []any  `json:"Groups,omitempty"`
}

type Device struct {
	IPAddress   string
	PhysAddress string
	Name        string
}

func rebootCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "reboot",
		Short: "Reboots the livebox",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			_, err = executeRequest(address, contextID, cookie, "NMC", "reboot", map[string]any{"reason": "GUI_Reboot"})
			if err != nil {
				return err
			}

			fmt.Println("Livebox is rebooting...")
			return nil
		},
	}
}

func phoneCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "phone",
		Short: "Show recent phone calls",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			response, err := executeRequest(address, contextID, cookie, "VoiceService.VoiceApplication", "getCallList", map[string]any{"line": "1"})
			if err != nil {
				return err
			}

			fmt.Println(response)
			return nil
		},
	}
}

func speedCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "speed",
		Short: "Show the DSL Downstream and Upstream speeds",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			response, err := executeRequest(address, contextID, cookie, "NeMo.Intf.data", "getMIBs", map[string]any{
				"mibs": "dsl",
			})
			if err != nil {
				return err
			}

			var data struct {
				Result struct {
					Status struct {
						Dsl struct {
							Dsl0 struct {
								DownstreamCurrRate int `json:"DownstreamCurrRate"`
								UpstreamCurrRate   int `json:"UpstreamCurrRate"`
							} `json:"dsl0"`
						} `json:"dsl"`
					} `json:"status"`
				} `json:"result"`
			}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}

			if data.Result.Status.Dsl.Dsl0.DownstreamCurrRate == 0 && data.Result.Status.Dsl.Dsl0.UpstreamCurrRate == 0 {
				return fmt.Errorf("no DSL data found. Note that this command only works for DSL connections, not fiber.")
			}

			downstreamCurrRate := float64(data.Result.Status.Dsl.Dsl0.DownstreamCurrRate)
			upstreamCurrRate := float64(data.Result.Status.Dsl.Dsl0.UpstreamCurrRate)
			fmt.Printf("\033[91m↓ %.1f Mbps\033[0m\n\033[92m↑ %.1f Mbps\033[0m\n",
				downstreamCurrRate*0.96/1000,
				upstreamCurrRate*0.96/1000)
			return nil
		},
	}
}

func pinholeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "pinhole",
		Short: "Manage pinhole rules",
		Long: undent.Undent(`
			Manage IPv6 pinhole rules.

			Examples:
			  livebox pinhole ls
			  livebox pinhole set mypinhole --to-port 443 --to-ip
		`),
	}

	cmd.AddCommand(
		pinholeLsCmd(),
		pinholeSetCmd(),
		pinholeRmCmd(),
	)

	return cmd
}

func pinholeLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all pinhole rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			response, err := executeRequest(address, contextID, cookie, "Firewall", "getPinhole", map[string]any{})
			if err != nil {
				return err
			}

			// {"result":{"status":{"webui_tailscale":{"Id":"webui_tailscale","Origin":"webui","Description":"tailscale","Status":"Enabled","SourceInterface":"data","Protocol":"17","IPVersion":6,"SourcePort":"","DestinationPort":"41642","SourcePrefix":"","DestinationIPAddress":"fdd2:4769:8b41::207","DestinationMACAddress":"","Enable":true}}}}
			var data struct {
				Result struct {
					Status map[string]struct {
						ID                    string `json:"Id"`
						Origin                string `json:"Origin"`
						Description           string `json:"Description"`
						Status                string `json:"Status"`
						SourceInterface       string `json:"SourceInterface"`
						Protocol              string `json:"Protocol"`
						IPVersion             int    `json:"IPVersion"`
						SourcePort            string `json:"SourcePort"`
						DestinationPort       string `json:"DestinationPort"`
						SourcePrefix          string `json:"SourcePrefix"`
						DestinationIPAddress  string `json:"DestinationIPAddress"`
						DestinationMACAddress string `json:"DestinationMACAddress"`
						Enable                bool   `json:"Enable"`
					} `json:"status"`
				} `json:"result"`
			}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}

			var rows [][]string
			for _, rule := range data.Result.Status {
				rows = append(rows, []string{
					rule.ID,
					fmt.Sprintf("%s/%s", rule.DestinationPort, protocToString(rule.Protocol)),
					rule.DestinationIPAddress,
				})
			}
			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("ID", "to IP", "to port").
				Rows(rows...)

			fmt.Println(t.String())

			return nil
		},
	}
}

func protocToString(protocol string) string {
	switch protocol {
	case "6":
		return "tcp"
	case "17":
		return "udp"
	default:
		return "unknown"
	}
}

func pinholeSetCmd() *cobra.Command {
	var toPort, toIP, toMAC string
	var useUDP bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a firewall rule for IPv4",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			// Parse the flags
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the name of pinhole")
			}
			name := args[0]

			protocol := "6" // TCP
			if useUDP {
				protocol = "17" // UDP
			}

			params := map[string]any{
				"id":                    name,
				"origin":                "webui",
				"sourceInterface":       "data",
				"sourcePort":            "",
				"destinationPort":       toPort,
				"destinationIPAddress":  toIP,
				"destinationMACAddress": toMAC,
				"sourcePrefix":          "",
				"protocol":              protocol,
				"ipversion":             6,
				"enable":                true,
				"persistent":            true, // IPv6 only.
			}

			_, err = executeRequest(address, contextID, cookie, "Firewall", "setPinhole", params)
			if err != nil {
				return err
			}

			_, err = executeRequest(address, contextID, cookie, "Firewall", "commit", map[string]any{})
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&toPort, "to-port", "", "Destination port")
	cmd.Flags().StringVar(&toIP, "to-ip", "", "Destination IP address")
	cmd.Flags().StringVar(&toMAC, "to-mac", "", "Destination MAC address")
	cmd.Flags().BoolVar(&useUDP, "udp", false, "Use UDP instead of TCP. Default is TCP")

	cmd.MarkFlagRequired("to-port")
	cmd.MarkFlagRequired("to-ip")
	cmd.MarkFlagRequired("to-mac")

	return cmd
}

func pinholeRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Remove a pinhole rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the name of the rule")
			}
			name := args[0]

			payload := map[string]any{
				"id": name,
			}

			response, err := executeRequest(address, contextID, cookie, "Firewall", "deletePinhole", payload)
			if err != nil {
				return err
			}

			fmt.Println(response)
			return nil
		},
	}
}

func portForwardCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "port-forward",
		Short: "Manage forwarding rules",
		Long: undent.Undent(`
			Manage IPv4 port forwarding rules.

			Examples:
			  livebox port-forward ls
			  livebox port-forward set [--udp] pi443 --from-port 443 --to-port 443 --to-ip 192.168.1.160 --to-mac E4:5F:01:A6:65:FE
			  livebox port-forward rm pi443
		`),
	}

	cmd.AddCommand(
		portForwardLsCmd(),
		portForwardSetCmd(),
		portForwardRmCmd(),
	)

	return cmd
}

func portForwardLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all port forwarding rules",
		Long: undent.Undent(`
			List all port forwarding rules. By default, it sets a TCP rule. To set
			a UDP rule, use the --udp flag.

			Example:

			  livebox port-forward set [--udp] pi443 --from-port 443 --to-port 443 --to-ip 192.168.1.160 --to-mac E4:5F:01:A6:65:FE
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			response, err := executeRequest(address, contextID, cookie, "Firewall", "getPortForwarding", map[string]any{})
			if err != nil {
				return err
			}

			var data struct {
				Result struct {
					Status map[string]struct {
						ID                    string `json:"Id"`
						Origin                string `json:"Origin"`
						Description           string `json:"Description"`
						Status                string `json:"Status"`
						SourceInterface       string `json:"SourceInterface"`
						Protocol              string `json:"Protocol"`
						ExternalPort          string `json:"ExternalPort"`
						InternalPort          string `json:"InternalPort"`
						SourcePrefix          string `json:"SourcePrefix"`
						DestinationIPAddress  string `json:"DestinationIPAddress"`
						DestinationMACAddress string `json:"DestinationMACAddress"`
						LeaseDuration         int    `json:"LeaseDuration"`
						HairpinNAT            bool   `json:"HairpinNAT"`
						SymmetricSNAT         bool   `json:"SymmetricSNAT"`
						UPnPV1Compat          bool   `json:"UPnPV1Compat"`
						Enable                bool   `json:"Enable"`
					} `json:"status"`
				} `json:"result"`
			}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}
			var rows [][]string
			for _, rule := range data.Result.Status {
				rows = append(rows, []string{
					rule.ID,
					fmt.Sprintf("%s/%s", rule.ExternalPort, protocToString(rule.Protocol)),
					rule.DestinationIPAddress,
					rule.InternalPort,
				})
			}
			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("ID", "from", "to IP", "to port").
				Rows(rows...)

			fmt.Println(t.String())

			return nil
		},
	}
}

func portForwardSetCmd() *cobra.Command {
	var fromPort, toPort, toIP, toMAC string
	var useUDP bool
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set a port forwarding rule",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the name of the rule")
			}
			name := args[0]

			protocol := "6" // TCP
			if useUDP {
				protocol = "17" // UDP
			}

			params := map[string]any{
				"id":                    "webui_" + name,
				"description":           name,
				"sourcePort":            "",
				"externalPort":          fromPort,
				"internalPort":          toPort,
				"destinationIPAddress":  toIP,
				"destinationMACAddress": toMAC, // Can be left empty.
				"enable":                true,
				"persistent":            true,
				"protocol":              protocol,
				"sourceInterface":       "data",
				"origin":                "webui",
				"sourcePrefix":          "",
				"ipversion":             4, // IPv4 only.
			}

			response, err := executeRequest(address, contextID, cookie, "Firewall", "setPortForwarding", params)
			var sErr APIErrors
			switch {
			case errors.As(err, &sErr):
				// Check if the rule is overlapping another rule. The error is:
				//  {"error": 1114120,"description": "Overlapping rule","info": "Port overlap detected: port[41642-41642] name[webui_tailscale2]"}
				e, ok := sErr.GetCode(1114120)
				if ok {
					return fmt.Errorf(undent.Undent(`
						%s
						You can remove the overlapping rule using:
						  livebox port-forward rm (<name>|<id>)
					`), e.Info)
				}
			case err != nil:
				return err
			}

			// To be parsed:
			// 	{"result":{"status":"webui_pi443","data":{"sourcePort":"","rule":{"Id":"webui_pi443","Origin":"webui","Description":"pi443","Status":"Error","SourceInterface":"data","Protocol":"6","ExternalPort":"443","ExternalPortEndRange":0,"InternalPort":"443","SourcePrefix":"","DestinationIPAddress":"192.168.1.160","DestinationMACAddress":"E4:5F:01:A6:65:FE","LeaseDuration":0,"HairpinNAT":true,"SymmetricSNAT":false,"UPnPV1Compat":false,"Enable":true}}}}
			var data struct {
				Result struct {
					Data struct {
						Rule struct {
							Status        string `json:"Status"` // "Enabled", "Error".
							LeaseDuration int    `json:"LeaseDuration"`
							HairpinNAT    bool   `json:"HairpinNAT"`
							SymmetricSNAT bool   `json:"SymmetricSNAT"`
							UPnPV1Compat  bool   `json:"UPnPV1Compat"`
							Enable        bool   `json:"Enable"`
						} `json:"rule"`
					} `json:"data"`
				} `json:"result"`
			}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}

			if data.Result.Data.Rule.Status != "Enabled" {
				return fmt.Errorf("failed to enable rule: %s", data.Result.Data.Rule.Status)
			}

			fmt.Printf("Successfully set rule. Lease duration: %d, Hairpin NAT: %t, Symmetric SNAT: %t\n",
				data.Result.Data.Rule.LeaseDuration,
				data.Result.Data.Rule.HairpinNAT,
				data.Result.Data.Rule.SymmetricSNAT,
			)
			return nil
		},
	}
	cmd.Flags().StringVar(&fromPort, "from-port", "", "Port to be forwarded")
	cmd.Flags().StringVar(&toPort, "to-port", "", "Destination port")
	cmd.Flags().StringVar(&toIP, "to-ip", "", "Destination IP address")
	cmd.Flags().StringVar(&toMAC, "to-mac", "", "Destination MAC address")
	cmd.Flags().BoolVar(&useUDP, "udp", false, "Use UDP instead of TCP. Default is TCP")

	cmd.MarkFlagRequired("from-port")
	cmd.MarkFlagRequired("to-port")
	cmd.MarkFlagRequired("to-ip")
	return cmd
}

func portForwardRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Remove a port forwarding rule",
		Args:  cobra.ExactArgs(1),
		Long: undent.Undent(`
			Remove a port forwarding rule. The argument is the name of the rule
			as seen in the UI. You can also pass the ID of the rule, which would
			be the name prefixed by "webui_".

			Usage:
			  livebox port-forward rm (<name>|<id>)

			Example:
			  livebox port-forward rm pi443
			  livebox port-forward rm webui_pi443
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the name of the rule to remove")
			}
			id := args[0]

			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			// If the ID doesn't start with "webui_", we add it.
			if !strings.HasPrefix(id, "webui_") {
				id = "webui_" + id
			}

			params := map[string]any{
				"id":     id,
				"origin": "webui",
			}
			response, err := executeRequest(address, contextID, cookie, "Firewall", "deletePortForwarding", params)
			var aErr APIErrors
			switch {
			case errors.As(err, &aErr):
				// Let's give a nice message when the rule doesn't exist. For
				// context, the error looks like this:
				//  1114115: Object not found: webui_tailscale2
				e, ok := aErr.GetCode(1114115)
				if ok {
					return fmt.Errorf("rule not found: %s", e.Info)
				}
			case err != nil:
				return fmt.Errorf("failed to remove rule: %w", err)
			}

			var data struct {
				Result struct {
					Status bool `json:"status"`
				} `json:"result"`
			}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}
			if !data.Result.Status {
				return fmt.Errorf("failed to remove rule, body: %s", response)
			}
			return nil
		},
	}
}

func staticLeaseCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "static-lease",
		Short: "Manage static leases",
		Long: undent.Undent(`
			Manage static leases.

			Examples:
			  livebox static-lease ls
			  livebox static-lease set 00:11:22:33:44:55 192.168.1.160
			  livebox static-lease rm 00:11:22:33:44:55
		`),
	}

	cmd.AddCommand(
		staticLeaseLsCmd(),
		staticLeaseSetCmd(),
		staticLeaseRmCmd(),
	)

	return cmd
}

func staticLeaseLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all static leases",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			leases, err := getStaticLeases(address, contextID, cookie)
			if err != nil {
				return fmt.Errorf("failed to get static leases: %w", err)
			}

			var rows [][]string
			for _, lease := range leases {
				rows = append(rows, []string{
					lease.MACAddress,
					lease.IPAddress,
				})
			}
			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("MAC address", "IP address").
				Rows(rows...)

			fmt.Println(t.String())

			return nil
		},
	}
}

func staticLeaseRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Remove a static lease",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			mac := args[0]

			leases, err := getStaticLeases(address, contextID, cookie)
			if err != nil {
				return fmt.Errorf("failed to get static leases: %w", err)
			}

			var leasePath string
			for _, lease := range leases {
				if lease.MACAddress == mac {
					leasePath = lease.LeasePath
					break
				}
			}

			if leasePath == "" {
				return fmt.Errorf("no lease found for MAC %s", mac)
			}

			params := map[string]any{
				"LeasePath": leasePath,
			}

			response, err := executeRequest(address, contextID, cookie, "DHCPv4.Server.Pool.default", "deleteStaticLease", params)
			if err != nil {
				return err
			}

			fmt.Println(response)
			return nil
		},
	}
}

func staticLeaseSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set an static lease",
		Long: undent.Undent(`
			Set a static lease.

			Example:
			  livebox dns set D8:10:68:8A:E9:C4 my-custom-name
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			mac := args[0]
			ip := args[1]

			leases, err := getStaticLeases(address, contextID, cookie)
			if err != nil {
				return fmt.Errorf("failed to get static leases: %w", err)
			}

			for _, lease := range leases {
				if lease.MACAddress == mac && lease.IPAddress == ip {
					fmt.Println("Lease already present, nothing to do")
					return nil
				}
				if lease.IPAddress == ip {
					return fmt.Errorf("IP address %s already has a lease for the MAC %s", ip, lease.MACAddress)
				}
				if lease.MACAddress == mac {
					return fmt.Errorf("MAC address already reserved for the IP %s", lease.IPAddress)
				}
			}

			params := map[string]any{
				"MACAddress": mac,
				"IPAddress":  ip,
			}

			_, err = executeRequest(address, contextID, cookie, "DHCPv4.Server.Pool.default", "addStaticLease", params)
			// Example of error response:
			//  * 0: Success: MACAddress
			//  * 393221: IP address already reserved:
			//  * 196639: Function execution failed: addStaticLease
			var apiErrs APIErrors
			if errors.As(err, &apiErrs) {
				for _, apiErr := range apiErrs {
					if apiErr.ErrorCode == 393221 {
						return fmt.Errorf("IP address already reserved")
					}
				}
			}
			if err != nil {
				return err
			}

			return nil
		},
	}

	return cmd
}

func dmzGetCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "get",
		Short: "Get the current IP configured in the DMZ",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			ip, err := getDMZ(address, contextID, cookie)
			if err != nil {
				if errors.Is(err, ErrNoDMZ) {
					return fmt.Errorf("no DMZ configured")
				}
				return err
			}

			fmt.Println(ip)
			return nil
		},
	}
}

func dmzSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set the DMZ configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the IPv4 address to set as DMZ")
			}
			ip := args[0]

			err = setDMZ(address, contextID, cookie, ip)
			if err != nil {
				return fmt.Errorf("failed to set DMZ: %w", err)
			}

			return nil
		},
	}

	return cmd
}

type StaticLease struct {
	IPAddress  string `json:"IPAddress"`
	MACAddress string `json:"MACAddress"`
	LeasePath  string `json:"LeasePath"`
}

func getStaticLeases(address, contextID string, cookie *http.Cookie) ([]StaticLease, error) {
	params := map[string]any{
		"default": "",
	}
	response, err := executeRequest(address, contextID, cookie, "DHCPv4.Server.Pool.default", "getStaticLeases", params)
	if err != nil {
		return nil, err
	}

	var data struct {
		Result struct {
			Status []StaticLease `json:"status"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(response), &data)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal response: %w", err)
	}

	return data.Result.Status, nil
}

func dmzCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dmz",
		Short: "Manage DMZ",
		Long: undent.Undent(`
			Manage DMZ.

			Examples:
			  livebox dmz get
			  livebox dmz set
			  livebox dmz rm
		`),
	}

	cmd.AddCommand(
		dmzGetCmd(),
		dmzSetCmd(),
		dmzRmCmd(),
	)

	return cmd
}

func dmzRmCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rm",
		Short: "Remove the DMZ configuration.",
		Long: undent.Undent(`
			Remove the DMZ configuration.

			There is only one DMZ configuration possible, so no need to specify an IP address.
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			err = deleteDMZ(address, contextID, cookie)
			if err != nil {
				return fmt.Errorf("failed to delete DMZ: %w", err)
			}

			return nil
		},
	}
}

var (
	ErrNoDMZ = fmt.Errorf("no DMZ configured")
)

// To know if no DMZ was found, you can use:
//
//	errors.Is(err, ErrNoDMZ)
func getDMZ(address, contextID string, cookie *http.Cookie) (ip string, _ error) {
	response, err := executeRequest(address, contextID, cookie, "Firewall", "getDMZ", map[string]any{})
	if err != nil {
		return "", err
	}

	var data struct {
		Result struct {
			Status struct {
				WebUI struct {
					SourceInterface      string `json:"SourceInterface"`      // "data"
					DestinationIPAddress string `json:"DestinationIPAddress"` // "192.168.1.160"
					SourcePrefix         string `json:"SourcePrefix"`         // ""
					Status               string `json:"Status"`               // "Enabled"
					Enable               bool   `json:"Enable"`               // true
				} `json:"webui"`
			} `json:"status"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(response), &data)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal response: %w", err)
	}
	if data.Result.Status.WebUI.Status == "" {
		return "", ErrNoDMZ
	}

	return data.Result.Status.WebUI.DestinationIPAddress, nil
}

func setDMZ(address, contextID string, cookie *http.Cookie, ip string) error {
	resp, err := executeRequest(address, contextID, cookie, "Firewall", "setDMZ", map[string]any{
		"id":                   "webui",
		"sourceInterface":      "data",
		"destinationIPAddress": ip,
		"enable":               true,
	})
	if err != nil {
		return err
	}

	var data struct {
		Result struct {
			Status string `json:"status"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(resp), &data)
	if err != nil {
		return err
	}
	if data.Result.Status != "webui" {
		return fmt.Errorf("failed to set DMZ: %s", resp)
	}

	return nil
}

func deleteDMZ(address, contextID string, cookie *http.Cookie) error {
	ip, err := getDMZ(address, contextID, cookie)
	switch {
	case errors.Is(err, ErrNoDMZ):
		fmt.Println("No DMZ configured, nothing to do")
		return nil
	case err != nil:
		return fmt.Errorf("failed to get DMZ: %w", err)
	}

	fmt.Printf("Removing DMZ for IP %s\n", ip)

	resp, err := executeRequest(address, contextID, cookie, "Firewall", "deleteDMZ", map[string]any{
		"id": "webui",
	})
	if err != nil {
		return err
	}

	var data struct {
		Result struct {
			Status bool `json:"status"` // true
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(resp), &data)
	if err != nil {
		return err
	}
	if !data.Result.Status {
		return fmt.Errorf("failed to delete DMZ: %s", resp)
	}

	return nil
}

func mergeFlagsWithConfig(config Config) (address, username, password string) {
	address = liveboxAddress
	if address == "" {
		address = config.Address
	}
	username = liveboxUsername
	if username == "" {
		username = config.Username
	}
	password = liveboxPassword
	if password == "" {
		password = config.Password
	}
	return address, username, password
}

func apiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "Send a raw API request from stdin",
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			// Read the JSON payload from stdin.
			payloadBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read payload from stdin: %w", err)
			}

			requestURL := fmt.Sprintf("http://%s/ws", address)
			req, err := http.NewRequest("POST", requestURL, bytes.NewBuffer(payloadBytes))
			if err != nil {
				return fmt.Errorf("failed to create request: %w", err)
			}

			req.Header.Set("Authorization", "X-Sah "+contextID)
			req.Header.Set("Content-Type", "application/x-sah-ws-4-call+json")
			req.AddCookie(cookie)
			req.AddCookie(&http.Cookie{Name: "sah/contextId", Value: contextID})
			req.Header.Set("X-Context", contextID)

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				return fmt.Errorf("failed to execute request: %w", err)
			}
			defer resp.Body.Close()

			// Print body to stdout.
			_, err = io.Copy(os.Stdout, resp.Body)
			if err != nil {
				return fmt.Errorf("failed to print response to stdout: %w", err)
			}
			return nil
		},
	}
}

func wifiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "wifi",
		Short: "Set the WLAN configuration",
		Long: undent.Undent(`
			Set the WLAN configuration. Without a pass, the security is set to
			"None". With a pass, the security is set to "WP2-Personal".

			To configure the SSID and pass code for the 2.4 GHz and 5 GHz
			bands simultaneously:

			  livebox wifi config --ssid "Wifi-Valais" --pass "foobar" --24ghz --5ghz

			If you omit "--24ghz --5ghz", both bands will be configured
			simultanously:

			  livebox wifi config --ssid "Wifi-Valais" --pass "foobar"

			If you want to configure different settings for each band:

			  livebox wifi config --24ghz --ssid "Wifi-Valais" --pass "foobar"
			  livebox wifi config --5ghz --ssid "Wifi-Valais_5GHz" --pass "foobar"

			To turn off both and turn on both bands:

			  livebox wifi disable
			  livebox wifi enable

			To turn on and off only one band:

			  livebox wifi disable --24ghz
			  livebox wifi enable --5ghz
		`),
	}

	var (
		ghz24 bool
		ghz5  bool
	)

	cmd.PersistentFlags().BoolVar(&ghz24, "24ghz", false, "Apply settings to 2.4GHz band")
	cmd.PersistentFlags().BoolVar(&ghz5, "5ghz", false, "Apply settings to 5GHz band")

	wlanEnableCmd := func() *cobra.Command {
		cmd := &cobra.Command{
			Use:   "enable",
			Short: "Enable WLAN",
			RunE:  enableDisableWLANCmd(&ghz5, &ghz24, "enable"),
		}
		return cmd
	}()
	wlanDisableCmd := func() *cobra.Command {
		cmd := &cobra.Command{
			Use:   "disable",
			Short: "Disable WLAN",
			RunE:  enableDisableWLANCmd(&ghz5, &ghz24, "disable"),
		}
		return cmd
	}()

	wlanConfigCmd := func() *cobra.Command {
		var ssid, pass string
		cmd := &cobra.Command{
			Use:   "config",
			Short: "Configure WLAN settings",
			RunE: func(cmd *cobra.Command, args []string) error {
				config, err := loadConfig()
				if err != nil {
					return err
				}
				address, username, password := mergeFlagsWithConfig(config)

				contextID, cookie, err := authenticate(address, username, password)
				if err != nil {
					return err
				}

				// Determine the security mode based on whether a password is provided.
				securityMode := "None"
				if pass != "" {
					securityMode = "WP2-Personal"
				}

				// If neither 2.4GHz nor 5GHz is specified, apply to both.
				if !ghz24 && !ghz5 {
					ghz24 = true
					ghz5 = true
				}

				wlanvap := make(map[string]any)
				if ghz24 {
					wlanvap["wl0"] = map[string]any{
						"SSID":                     ssid,
						"SSIDAdvertisementEnabled": true,
						"Security":                 map[string]any{"ModeEnabled": securityMode, "KeyPassPhrase": pass},
						"MACFiltering":             map[string]any{"Mode": "Off"},
						"WPS":                      map[string]any{"Enable": false},
					}
				}
				if ghz5 {
					wlanvap["eth4"] = map[string]any{
						"SSID":                     ssid,
						"SSIDAdvertisementEnabled": true,
						"Security":                 map[string]any{"ModeEnabled": securityMode, "KeyPassPhrase": pass},
						"MACFiltering":             map[string]any{"Mode": "Off"},
						"WPS":                      map[string]any{"Enable": false},
					}
				}

				params := map[string]any{
					"mibs": map[string]any{"wlanvap": wlanvap},
				}
				_, err = executeRequest(address, contextID, cookie, "NeMo.Intf.lan", "setWLANConfig", params)
				if err != nil {
					return fmt.Errorf("failed to set WLAN config: %w", err)
				}

				fmt.Println("WLAN configuration updated successfully")
				return nil
			},
		}

		cmd.Flags().StringVar(&ssid, "ssid", "", "WLAN SSID")
		cmd.Flags().StringVar(&pass, "pass", "", "WLAN password")
		if err := cmd.MarkFlagRequired("ssid"); err != nil {
			panic(err) // MarkFlagRequired only returns an error when the flag does not exist
		}
		return cmd
	}()

	cmd.AddCommand(
		wlanEnableCmd,
		wlanDisableCmd,
		wlanConfigCmd,
	)

	return cmd
}

// Action = "enable" or "disable".
func enableDisableWLANCmd(ghz5, ghz24 *bool, action string) func(cmd *cobra.Command, args []string) error {
	return func(cmd *cobra.Command, args []string) error {
		config, err := loadConfig()
		if err != nil {
			return err
		}
		address, username, password := mergeFlagsWithConfig(config)

		contextID, cookie, err := authenticate(address, username, password)
		if err != nil {
			return err
		}

		// If neither 2.4GHz nor 5GHz is specified, apply to both.
		if !*ghz24 && !*ghz5 {
			*ghz24 = true
			*ghz5 = true
		}

		enable := false
		if action == "enable" {
			enable = true
		}

		penable := make(map[string]any)
		if *ghz5 {
			penable["eth4"] = map[string]any{
				"Enable":           enable,
				"PersistentEnable": true,
				"Status":           true,
			}
		}
		if *ghz24 {
			penable["wl0"] = map[string]any{
				"Enable":           enable,
				"PersistentEnable": true,
				"Status":           true,
			}
		}

		params := map[string]any{
			"mibs": map[string]any{
				"penable": penable,
			},
		}

		_, err = executeRequest(address, contextID, cookie, "NeMo.Intf.lan", "setWLANConfig", params)
		if err != nil {
			return fmt.Errorf("failed to set WLAN config: %w", err)
		}

		return nil
	}
}

func dnsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns",
		Short: "Set the name of a device",
		Long: undent.Undent(`
			Set the name of a device.

			Example:
			  livebox dns set D8:10:68:8A:F0:D2 foobar
		`),
	}
	cmd.AddCommand(dnsSetCmd(), dnsLsCmd())
	return cmd
}

func dnsSetCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "set",
		Short: "Set the name of a device",
		Long: undent.Undent(`
			Set the name of a device.

			Example:
			  livebox dns set D8:10:68:8A:F0:D2 foobar
		`),
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			mac := args[0]
			name := args[1]

			// Example:
			// {"service":"Devices.Device.D8:10:68:8A:F0:D2","method":"setName","parameters":{"name":"my-custom-name","source":"dns"}}
			_, err = executeRequest(address, contextID, cookie, "Devices.Device."+mac, "setName", map[string]any{
				"name":   name,
				"source": "dns",
			})
			if err != nil {
				return fmt.Errorf("failed to set name: %w", err)
			}

			return nil
		},
	}
	return cmd
}

func dnsLsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ls",
		Short: "List all devices",
		Long: undent.Undent(`
			List all devices.

			Example:
			  livebox dns ls
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)

			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			devices, err := getDevices(address, contextID, cookie)
			if err != nil {
				return fmt.Errorf("failed to get devices: %w", err)
			}

			var rows [][]string
			for _, dev := range devices {
				rows = append(rows, []string{
					dev.IPv4,
					dev.MacAddress,
					strings.Join(dev.Names, ", "),
				})
			}
			t := table.New().
				Border(lipgloss.NormalBorder()).
				Headers("IP address", "MAC address", "Name").
				Rows(rows...)

			fmt.Println(t.String())

			return nil
		},
	}
	return cmd
}

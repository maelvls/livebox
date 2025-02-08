package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/goccy/go-yaml"
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
		Use:           "livebox",
		Short:         "A CLI for interacting with a Livebox 4 or 5 (Orange)",
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	rootCmd.PersistentFlags().StringVar(&liveboxAddress, "address", "", "IP or hostname of the livebox")
	rootCmd.PersistentFlags().StringVar(&liveboxUsername, "username", "", "Username to use for authentication")
	rootCmd.PersistentFlags().StringVar(&liveboxPassword, "password", "", "Password to use for authentication")
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Enable debug output")

	rootCmd.AddCommand(
		newLoginCmd(),
		newLsCmd(),
		newRebootCmd(),
		newPhoneCmd(),
		newSpeedCmd(),
		newSpeedRawCmd(),
		newDslCmd(),
		newFirewallCmd(),
		newAddPinholeCmd(),
		newApiCmd(),
		newSetPortForwarding(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func authenticate(address, username, password string) (contextID string, sessid *http.Cookie, _ error) {
	authURL := fmt.Sprintf("http://%s/ws", address)
	payloadBytes, err := json.Marshal(map[string]interface{}{
		"service": "sah.Device.Information",
		"method":  "createContext",
		"parameters": map[string]interface{}{
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
func executeRequest(address, contextID string, cookie *http.Cookie, service, method string, parameters map[string]interface{}) (string, error) {
	requestURL := fmt.Sprintf("http://%s/ws", address)

	payload := map[string]interface{}{
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

	// Example error response:
	// 	{"result":{"status":null,"errors":[{"error":13,"description":"Permission denied","info":"TopologyDiagnostics"}]}}
	//  {"result":{"status":null,"errors":[{"error":196640,"description":"Missing mandatory argument","info":"origin"},{"error":196640,"description":"Missing mandatory argument","info":"sourceInterface"},{"error":196640,"description":"Missing mandatory argument","info":"internalPort"},{"error":196640,"description":"Missing mandatory argument","info":"destinationIPAddress"},{"error":196640,"description":"Missing mandatory argument","info":"protocol"}]}}
	var result struct {
		Result struct {
			Status interface{} `json:"status"`
			Errors []struct {
				Error       int    `json:"error"`
				Description string `json:"description"`
				Info        string `json:"info"`
			} `json:"errors"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(bodyBytes), &result)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal result: %w", err)
	}
	if len(result.Result.Errors) > 0 {
		var errs []string
		for _, err := range result.Result.Errors {
			errs = append(errs, fmt.Sprintf("  * %d: %s: %s", err.Error, err.Description, err.Info))
		}
		return "", fmt.Errorf("%s, %s:\n%s", service, method, strings.Join(errs, "\n"))
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return string(bodyBytes), nil
}

func newLoginCmd() *cobra.Command {
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

func newLsCmd() *cobra.Command {
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

			response, err := executeRequest(address, contextID, cookie, "TopologyDiagnostics", "buildTopology", map[string]interface{}{"SendXmlFile": false})
			if err != nil {
				return err
			}

			// Parse the JSON response and extract the IP addresses, MAC
			// addresses, and names.
			var data map[string]interface{}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}

			// Extract the devices from the response.
			devices := extractDevices(data)

			// Print the devices.
			for _, device := range devices {
				fmt.Printf("%s %s %s\n", device.IPAddress, device.PhysAddress, device.Name)
			}

			return nil
		},
	}
}

type Device struct {
	IPAddress   string
	PhysAddress string
	Name        string
}

func extractDevices(data map[string]interface{}) []Device {
	var devices []Device
	extractDevicesRecursive(data, &devices)
	return devices
}

func extractDevicesRecursive(data interface{}, devices *[]Device) {
	switch v := data.(type) {
	case map[string]interface{}:
		if name, ok := v["Name"].(string); ok {
			if ipAddress, ok := v["IPAddress"].(string); ok && ipAddress != "" {
				physAddress := ""
				if physAddressRaw, ok := v["PhysAddress"]; ok {
					physAddress = fmt.Sprintf("%v", physAddressRaw)
				}
				*devices = append(*devices, Device{
					IPAddress:   ipAddress,
					PhysAddress: physAddress,
					Name:        name,
				})
			}
		}
		for _, value := range v {
			extractDevicesRecursive(value, devices)
		}
	case []interface{}:
		for _, value := range v {
			extractDevicesRecursive(value, devices)
		}
	}
}

func newRebootCmd() *cobra.Command {
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

			_, err = executeRequest(address, contextID, cookie, "NMC", "reboot", map[string]interface{}{"reason": "GUI_Reboot"})
			if err != nil {
				return err
			}

			fmt.Println("Livebox is rebooting...")
			return nil
		},
	}
}

func newPhoneCmd() *cobra.Command {
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

			response, err := executeRequest(address, contextID, cookie, "VoiceService.VoiceApplication", "getCallList", map[string]interface{}{"line": "1"})
			if err != nil {
				return err
			}

			fmt.Println(response)
			return nil
		},
	}
}

func newSpeedCmd() *cobra.Command {
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

			response, err := executeRequest(address, contextID, cookie, "NeMo.Intf.data", "getMIBs", map[string]interface{}{"mibs": "dsl"})
			if err != nil {
				return err
			}

			var data map[string]interface{}
			err = json.Unmarshal([]byte(response), &data)
			if err != nil {
				return fmt.Errorf("failed to unmarshal response: %w", err)
			}

			status, ok := data["result"].(map[string]interface{})["status"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("could not find result.status in response")
			}
			dsl0, ok := status["dsl"].(map[string]interface{})["dsl0"].(map[string]interface{})
			if !ok {
				return fmt.Errorf("could not find result.status.dsl.dsl0 in response")
			}

			downstreamCurrRate, ok := dsl0["DownstreamCurrRate"].(float64)
			if !ok {
				return fmt.Errorf("could not find result.status.dsl.dsl0.DownstreamCurrRate in response")
			}
			upstreamCurrRate, ok := dsl0["UpstreamCurrRate"].(float64)
			if !ok {
				return fmt.Errorf("could not find result.status.dsl.dsl0.UpstreamCurrRate in response")
			}

			fmt.Printf("\033[91m↓ %.1f Mbps\033[0m\n\033[92m↑ %.1f Mbps\033[0m\n", downstreamCurrRate*0.96/1000, upstreamCurrRate*0.96/1000)

			return nil
		},
	}
}

func newSpeedRawCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "speedraw",
		Short: "Show the output of NeMo.Intf.data/getMIBs",
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

			response, err := executeRequest(address, contextID, cookie, "NeMo.Intf.data", "getMIBs", map[string]interface{}{"mibs": "dsl"})
			if err != nil {
				return err
			}

			fmt.Println(response)
			return nil
		},
	}
}

func newDslCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "dsl",
		Short: "Show the output of NeMo.Intf.dsl0/getDSLStats",
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

			services := []string{"NMC", "NetMaster", "NeMo.Intf.dsl0"}
			methods := map[string][]string{
				"NMC":            {"get"},
				"NetMaster":      {"getWANModeList", "getInterfaceConfig"},
				"NeMo.Intf.dsl0": {"getDSLStats"},
			}

			for _, service := range services {
				for _, method := range methods[service] {
					var params map[string]interface{}
					if method == "getInterfaceConfig" {
						params = map[string]interface{}{"name": "VDSL_DHCP"}
					} else {
						params = map[string]interface{}{}
					}
					response, err := executeRequest(address, contextID, cookie, service, method, params)
					if err != nil {
						fmt.Printf("Error calling %s/%s: %v\n", service, method, err)
						continue
					}
					fmt.Printf("Response from %s/%s:\n%s\n", service, method, response)
				}
			}

			return nil
		},
	}
}

func newFirewallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "firewall",
		Short: "List firewall IPv4 settings",
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

			printFirewallRules := func(ipVersion string) error {
				var method string
				switch ipVersion {
				case "IPv4":
					method = "getPortForwarding"
				case "IPv6":
					method = "getPinhole"
				default:
					return fmt.Errorf("invalid IP version: %s", ipVersion)
				}

				response, err := executeRequest(address, contextID, cookie, "Firewall", method, map[string]interface{}{})
				if err != nil {
					return err
				}

				var data map[string]interface{}
				err = json.Unmarshal([]byte(response), &data)
				if err != nil {
					return fmt.Errorf("failed to unmarshal response: %w", err)
				}

				status, ok := data["status"].([]interface{})
				if !ok {
					fmt.Println(response)
					return fmt.Errorf("could not find status in response")
				}

				for _, rule := range status {
					ruleData, ok := rule.(map[string]interface{})
					if !ok {
						fmt.Printf("Invalid rule data: %v\n", rule)
						continue
					}

					var protocol, sourcePrefix, externalPort, destinationIPAddress, internalPort, id string
					switch ipVersion {
					case "IPv4":
						protocol = fmt.Sprintf("%v", ruleData["Protocol"])
						sourcePrefix = fmt.Sprintf("%v", ruleData["SourcePrefix"])
						externalPort = fmt.Sprintf("%v", ruleData["ExternalPort"])
						destinationIPAddress = fmt.Sprintf("%v", ruleData["DestinationIPAddress"])
						internalPort = fmt.Sprintf("%v", ruleData["InternalPort"])
						id = fmt.Sprintf("%v", ruleData["Id"])

						fmt.Printf("%s %s\t%s:%s\t-> %s:%s\t%s\n", ipVersion, protocol, sourcePrefix, externalPort, destinationIPAddress, internalPort, id)
					case "IPv6":
						protocol = fmt.Sprintf("%v", ruleData["Protocol"])
						sourcePrefix = fmt.Sprintf("%v", ruleData["SourcePrefix"])
						externalPort = fmt.Sprintf("%v", ruleData["SourcePort"])
						destinationIPAddress = fmt.Sprintf("%v", ruleData["DestinationIPAddress"])
						internalPort = fmt.Sprintf("%v", ruleData["DestinationPort"])
						id = fmt.Sprintf("%v", ruleData["Id"])

						fmt.Printf("%s %s\t%s:%s\t-> %s:%s\t%s\n", ipVersion, protocol, sourcePrefix, externalPort, destinationIPAddress, internalPort, id)
					}
				}
				return nil
			}

			if err := printFirewallRules("IPv4"); err != nil {
				return err
			}
			if err := printFirewallRules("IPv6"); err != nil {
				return err
			}

			return nil
		},
	}
}

func newAddPinholeCmd() *cobra.Command {
	// Example:
	//  livebox set-pinhole tailscale-udp --dst-port 443 --dst-ip 192.168.1.200 --dst-mac 00:11:32:e1:21:5c
	//
	// Result:
	//  livebox --address livebox:8080 --password "$password" api <<EOF | jq
	//  {
	//    "service": "Firewall",
	//    "method": "setPinhole",
	//    "parameters": {
	//      "id": "https",
	//      "origin": "webui",
	//      "sourceInterface": "data",
	//      "sourcePort": "",
	//      "destinationPort": "443",
	//      "destinationIPAddress": "192.168.1.200",
	//      "destinationMACAddress": "00:11:32:e1:21:5c",
	//      "sourcePrefix": "",
	//      "protocol": "6",
	//      "ipversion": 6,
	//      "enable": true,
	//      "persistent": true
	//    }
	//  }
	//  EOF
	cmd := &cobra.Command{
		Use:   "set-pinhole",
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
			dstPort, err := cmd.Flags().GetString("dst-port")
			if err != nil {
				return fmt.Errorf("--dst-port required")
			}
			dstIP, err := cmd.Flags().GetString("dst-ip")
			if err != nil {
				return fmt.Errorf("--dst-ip required")
			}
			dstMAC, err := cmd.Flags().GetString("dst-mac")
			if err != nil {
				return fmt.Errorf("--dst-mac required")
			}

			payload := map[string]interface{}{
				"service": "Firewall",
				"method":  "setPortForwarding",
				"parameters": map[string]interface{}{
					"id":                    name,
					"origin":                "webui",
					"sourceInterface":       "data",
					"sourcePort":            "",
					"destinationPort":       dstPort,
					"destinationIPAddress":  dstIP,
					"destinationMACAddress": dstMAC,
					"sourcePrefix":          "",
					"protocol":              "6",
					"ipversion":             6,
					"enable":                true,
					"persistent":            true,
				},
			}

			response, err := executeRequest(address, contextID, cookie, "Firewall", "setPortForwarding", payload)
			if err != nil {
				return err
			}
			fmt.Println(response)

			_, err = executeRequest(address, contextID, cookie, "Firewall", "commit", map[string]interface{}{})
			if err != nil {
				return err
			}

			return nil
		},
	}

	cmd.Flags().String("dst-port", "", "Destination port")
	cmd.Flags().String("dst-ip", "", "Destination IP address")
	cmd.Flags().String("dst-mac", "", "Destination MAC address")

	return cmd
}

func newSetPortForwarding() *cobra.Command {
	var fromPort, toPort, toIP, toMAC string
	var useUDP bool
	cmd := &cobra.Command{
		Use:   "set-port-forwarding",
		Short: "Set a firewall rule",
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

			// Parse the flags.
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the name of the rule")
			}
			name := args[0]

			protocol := "6" // TCP
			if useUDP {
				protocol = "17" // UDP
			}

			params := map[string]interface{}{
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
			}

			response, err := executeRequest(address, contextID, cookie, "Firewall", "setPortForwarding", params)
			if err != nil {
				return err
			}

			// To be parsed:
			// 	{"result":{"status":"webui_pi443","data":{"sourcePort":"","rule":{"Id":"webui_pi443","Origin":"webui","Description":"pi443","Status":"Error","SourceInterface":"data","Protocol":"6","ExternalPort":"443","ExternalPortEndRange":0,"InternalPort":"443","SourcePrefix":"","DestinationIPAddress":"192.168.1.160","DestinationMACAddress":"E4:5F:01:A6:65:FE","LeaseDuration":0,"HairpinNAT":true,"SymmetricSNAT":false,"UPnPV1Compat":false,"Enable":true}}}}
			var data struct {
				Result struct {
					Data struct {
						Rule struct {
							Status        string `json:"Status"`
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

			fmt.Printf("Status: %s\nLeaseDuration: %d\nHairpinNAT: %t\nSymmetricSNAT: %t\nUPnPV1Compat: %t\n",
				data.Result.Data.Rule.Status,
				data.Result.Data.Rule.LeaseDuration,
				data.Result.Data.Rule.HairpinNAT,
				data.Result.Data.Rule.SymmetricSNAT,
				data.Result.Data.Rule.UPnPV1Compat,
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

func newApiCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "api",
		Short: "Send a raw API request",
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

			// Read the JSON payload from stdin
			payloadBytes, err := io.ReadAll(os.Stdin)
			if err != nil {
				return fmt.Errorf("failed to read payload from stdin: %w", err)
			}

			// Execute the request
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

			// Read the response body
			responseBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				return fmt.Errorf("failed to read response body: %w", err)
			}

			fmt.Println(string(responseBytes))
			return nil
		},
	}
}

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

	"github.com/charmbracelet/huh"
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
		loginCmd(),
		lsCmd(),
		rebootCmd(),
		phoneCmd(),
		speedCmd(),
		firewallCmd(),
		pinholeCmd(),
		apiCmd(),
		staticLeaseCmd(),
		dmzCmd(),
		wifiCmd(),
	)

	if err := rootCmd.Execute(); err != nil {
		fmt.Println("Error:", err)
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

// You can get the err info using:
//
//	var apiErrs APIErrors
//	errors.As(err, &apiErrs)
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
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status code: %d, body: %s", resp.StatusCode, string(bodyBytes))
	}

	// Example error response:
	// 	{"result":{"status":null,"errors":[{"error":13,"description":"Permission denied","info":"TopologyDiagnostics"}]}}
	//  {"result":{"status":null,"errors":[{"error":196640,"description":"Missing mandatory argument","info":"origin"},{"error":196640,"description":"Missing mandatory argument","info":"sourceInterface"},{"error":196640,"description":"Missing mandatory argument","info":"internalPort"},{"error":196640,"description":"Missing mandatory argument","info":"destinationIPAddress"},{"error":196640,"description":"Missing mandatory argument","info":"protocol"}]}}
	var result struct {
		Result struct {
			Status interface{} `json:"status"`
			Errors APIErrors   `json:"errors"`
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
		return "", fmt.Errorf("while running method '%s' on service %s:\n%w", method, service, APIErrors(result.Result.Errors))
	}

	return string(bodyBytes), nil
}

type APIErrors []APIError

func (e APIErrors) Error() string {
	var errs []string
	for _, err := range e {
		errs = append(errs, fmt.Sprintf("  * %d: %s: %s", err.Error, err.Description, err.Info))
	}
	return strings.Join(errs, "\n")
}

func (e APIErrors) GetCode(code int) (APIError, bool) {
	for _, err := range e {
		if err.Error == code {
			return err, true
		}
	}
	return APIError{}, false
}

type APIError struct {
	Error       int    `json:"error"`
	Description string `json:"description"`
	Info        string `json:"info"`
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

			_, err = executeRequest(address, contextID, cookie, "NMC", "reboot", map[string]interface{}{"reason": "GUI_Reboot"})
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

			response, err := executeRequest(address, contextID, cookie, "VoiceService.VoiceApplication", "getCallList", map[string]interface{}{"line": "1"})
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

			response, err := executeRequest(address, contextID, cookie, "NeMo.Intf.data", "getMIBs", map[string]interface{}{
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

func firewallCmd() *cobra.Command {
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

			response, err := executeRequest(address, contextID, cookie, "Firewall", "getPinhole", map[string]interface{}{})
			if err != nil {
				return err
			}

			fmt.Println(response)
			return nil
		},
	}
}

func pinholeSetCmd() *cobra.Command {
	var toPort, toIP, toMAC string
	var useUDP bool
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

			protocol := "6" // TCP
			if useUDP {
				protocol = "17" // UDP
			}

			payload := map[string]interface{}{
				"service": "Firewall",
				"method":  "setPortForwarding",
				"parameters": map[string]interface{}{
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

			payload := map[string]interface{}{
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

			response, err := executeRequest(address, contextID, cookie, "Firewall", "getPortForwarding", map[string]interface{}{})
			if err != nil {
				return err
			}

			fmt.Println(response)
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

			// Parse the flags.
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
				"ipversion":             4, // IPv4 only.
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

			// Check if the rule is overlapping another rule. The error is:
			//  {
			//      "error": 1114120,
			//      "description": "Overlapping rule",
			//      "info": "Port overlap detected: port[41642-41642] name[webui_tailscale2]"
			//  }
			var sErr APIErrors
			if errors.As(err, &sErr) {
				e, ok := sErr.GetCode(196640)
				if ok {
					return fmt.Errorf("%s.", e.Info)
				}
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
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 1 {
				return fmt.Errorf("expected a single argument: the name of the rule to remove")
			}
			name := args[0]

			config, err := loadConfig()
			if err != nil {
				return err
			}
			address, username, password := mergeFlagsWithConfig(config)
			contextID, cookie, err := authenticate(address, username, password)
			if err != nil {
				return err
			}

			params := map[string]interface{}{
				"id": name,
			}
			response, err := executeRequest(address, contextID, cookie, "Firewall", "deletePortForwarding", params)
			if err != nil {
				return err
			}

			fmt.Println(response)
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

			for _, lease := range leases {
				fmt.Printf("%s %s %s\n", lease.IPAddress, lease.MACAddress, lease.LeasePath)
			}

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

			params := map[string]interface{}{
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
		Args:  cobra.ExactArgs(2),
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
					return fmt.Errorf("IP address already reserved with MAC %s", lease.MACAddress)
				}
				if lease.MACAddress == mac {
					return fmt.Errorf("MAC address already reserved for the IP %s", lease.IPAddress)
				}
			}

			params := map[string]interface{}{
				"MACAddress": mac,
				"IPAddress":  ip,
			}

			response, err := executeRequest(address, contextID, cookie, "DHCPv4.Server.Pool.default", "addStaticLease", params)
			// Example of error response:
			//  * 0: Success: MACAddress
			//  * 393221: IP address already reserved:
			//  * 196639: Function execution failed: addStaticLease
			var apiErrs APIErrors
			if errors.As(err, &apiErrs) {
				for _, apiErr := range apiErrs {
					if apiErr.Error == 393221 {
						return fmt.Errorf("IP address already reserved")
					}
				}
			}
			if err != nil {
				return err
			}

			fmt.Println(response)
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
	params := map[string]interface{}{
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
	response, err := executeRequest(address, contextID, cookie, "Firewall", "getDMZ", map[string]interface{}{})
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
	resp, err := executeRequest(address, contextID, cookie, "Firewall", "setDMZ", map[string]interface{}{
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

	resp, err := executeRequest(address, contextID, cookie, "Firewall", "deleteDMZ", map[string]interface{}{
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

func staticLeasesLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List static leases",
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
				return err
			}

			for _, lease := range leases {
				fmt.Printf("%s %s\n", lease.IPAddress, lease.MACAddress)
			}

			return nil
		},
	}
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

				wlanvap := make(map[string]interface{})
				if ghz24 {
					wlanvap["wl0"] = map[string]interface{}{
						"SSID":                     ssid,
						"SSIDAdvertisementEnabled": true,
						"Security":                 map[string]interface{}{"ModeEnabled": securityMode, "KeyPassPhrase": pass},
						"MACFiltering":             map[string]interface{}{"Mode": "Off"},
						"WPS":                      map[string]interface{}{"Enable": false},
					}
				}
				if ghz5 {
					wlanvap["eth4"] = map[string]interface{}{
						"SSID":                     ssid,
						"SSIDAdvertisementEnabled": true,
						"Security":                 map[string]interface{}{"ModeEnabled": securityMode, "KeyPassPhrase": pass},
						"MACFiltering":             map[string]interface{}{"Mode": "Off"},
						"WPS":                      map[string]interface{}{"Enable": false},
					}
				}

				params := map[string]interface{}{
					"mibs": map[string]interface{}{"wlanvap": wlanvap},
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

		penable := make(map[string]interface{})
		if *ghz5 {
			penable["eth4"] = map[string]interface{}{
				"Enable":           enable,
				"PersistentEnable": true,
				"Status":           true,
			}
		}
		if *ghz24 {
			penable["wl0"] = map[string]interface{}{
				"Enable":           enable,
				"PersistentEnable": true,
				"Status":           true,
			}
		}

		params := map[string]interface{}{
			"mibs": map[string]interface{}{
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

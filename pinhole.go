package main

import (
	"encoding/json"
	"net/http"
	"slices"
)

type Pinhole struct {
	Id                    string `json:"Id"`
	Origin                string `json:"Origin"`
	Description           string `json:"Description"`
	Status                string `json:"Status"`
	SourceInterface       string `json:"SourceInterface"`
	Protocol              string `json:"Protocol"`
	IPVersion             int    `json:"IPVersion"`
	SourcePort            string `json:"SourcePort"`
	DestinationPort       string `json:"DestinationPort"`
	DestinationIPAddress  string `json:"DestinationIPAddress"`
	DestinationMACAddress string `json:"DestinationMACAddress"`
	Enable                bool   `json:"Enable"`
}

func getPinholes(address, contextID string, cookie *http.Cookie) ([]Pinhole, error) {
	response, err := executeRequest(address, contextID, cookie, "Firewall", "getPinhole", map[string]any{})
	if err != nil {
		return nil, err
	}

	var data struct {
		Result struct {
			Status map[string]Pinhole `json:"status"`
		} `json:"result"`
	}
	err = json.Unmarshal([]byte(response), &data)
	if err != nil {
		return nil, err
	}

	pinholes := make([]Pinhole, 0, len(data.Result.Status))
	for _, pinhole := range data.Result.Status {
		pinholes = append(pinholes, pinhole)
	}

	// Let's sort this since Go maps are randomly ordered. We want the result of
	// this to be stable.
	slices.SortFunc(pinholes, func(a, b Pinhole) int {
		if a.Id < b.Id {
			return -1
		} else if a.Id > b.Id {
			return 1
		}
		return 0
	})

	return pinholes, nil
}

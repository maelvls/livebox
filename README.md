# livebox CLI for livebox v4

<img alt="livebox-speed-command" src="https://user-images.githubusercontent.com/2195781/114412685-9d8f6500-9bad-11eb-8911-0a571c0b578a.png" width="500">

`livebox` is a CLI I wrote to quickly reboot my Livebox 4 as well as to see the
modem's bandwidth. It also works with Livebox 5 models. The Livebox is an
all-in-one internet router that the French ISP Orange is renting to their
customers.

```sh
go install github.com/maelvls/livebox@latest
```

To get started:

```sh
livebox login
```

To list the devices on your network:

```sh
livebox ls
```

To reboot the Livebox:

```sh
livebox reboot
```

You can do raw API calls too:

```sh
livebox api <<<'{"service":"NeMo.Intf.lan","method":"getMIBs","parameters":{"mibs":"base wlanradio"}}'
```

Show your DSL speed (doesn't work for fiber connections, only DSL):

```sh
livebox speed
```

## Wi-fi

You can also configure your Wi-Fi. To configure the SSID and pass code for the
2.4 GHz and 5 GHz bands simultaneously:

```sh
livebox wifi config --ssid "Wifi-Valais" --pass "foobar" --24ghz --5ghz
```

If you omit both `--24ghz` and `--5ghz`, both bands will be configured
simultanously:

```sh
livebox wifi config --ssid "Wifi-Valais" --pass "foobar"
```

If you want to configure different settings for each band:

```sh
livebox wifi config --24ghz --ssid "Wifi-Valais" --pass "foobar"
livebox wifi config --5ghz --ssid "Wifi-Valais_5GHz" --pass "foobar"
```

To turn off both and turn on both bands:

```sh
livebox wifi disable
livebox wifi enable
```

To turn on and off only one band:

```sh
livebox wifi disable --24ghz
livebox wifi enable --5ghz
```

## Firewall

You can configure the firewall using the CLI.

For IPv4 TCP port forwarding:

```sh
livebox port-forward set pi443 --from-port 443 --to-port 443 --to-ip 192.168.1.160 --to-mac E4:5F:01:A6:65:FE
```

You can add the `--udp` flag to forward UDP traffic instead of TCP.

Regarding IPv6 pinholes, you can do that too:

```sh
livebox pinhole set tailscale-pi-ipv6 --to-port 41642 --to-ip 192.168.1.160 --to-mac e4:5f:01:a6:65:fe --udp
```

## DHCP

To configure a static lease:

```sh
livebox static-lease set bc:d0:74:32:e9:1a 192.168.1.155
```

To list the static leases:

```sh
livebox static-lease ls
```

## DMZ

To configure the DMZ:

```sh
livebox dmz set 192.168.1.160
```

Also, you can remove the DMZ and see if one is configured:

```sh
livebox dmz rm
livebox dmz get       # Returns the IP of the DMZ'ed device.
```

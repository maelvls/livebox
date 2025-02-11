# livebox CLI for the Livebox 4 and 5

My internet service provider is Orange. When you sign up for a plan with them, they provide a modem/router called the ‘Livebox.’ I’ve used two versions of it: Livebox 4 and Livebox 5. I had the Livebox 4 when I was limited to DSL, but once I became eligible for fiber in 2025, I was upgraded to the Livebox 5.

<!-- Table without border just to align the two images. Center text. -->

<table align="center" border="0">
  <tr>
    <td align="center">
      <img alt="livebox-v4-fs8" src="https://github.com/user-attachments/assets/12b3b3eb-a9be-45b6-868e-a12b414a041c" width="500">
        Livebox 4
    </td>
    <td align="center">
      <img alt="livebox-v5-fs8" src="https://github.com/user-attachments/assets/bf8bf5e2-b7e4-4cd8-9097-15c6fc440eb3" width="500">
      Livebox 5
      </td>
    </tr>
</table>

I developed the `livebox` CLI to quickly reboot the Livebox and monitor its bandwidth. The CLI is compatible with both Livebox 4 and Livebox 5 models.

## Getting started

```sh
go install github.com/maelvls/livebox@latest
```

To get started:

```sh
livebox login
```

You can now list the devices on your network to find out their IP and MAC
addresses:

```sh
livebox ls
```

You can reboot the Livebox from the command line:

```sh
livebox reboot
```

You can do raw API calls too:

```sh
livebox api <<<'{"service":"NeMo.Intf.lan","method":"getMIBs","parameters":{"mibs":"base wlanradio"}}'
```

You can display the DSL bandwidth (doesn't work for fiber connections, only DSL):

```sh
livebox speed
```

I had a very poor DSL connection back in the day:

![the speed command](https://user-images.githubusercontent.com/2195781/114412685-9d8f6500-9bad-11eb-8911-0a571c0b578a.png)

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

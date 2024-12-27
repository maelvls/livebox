# livebox CLI for livebox v4

<img alt="livebox-speed-command" src="https://user-images.githubusercontent.com/2195781/114412685-9d8f6500-9bad-11eb-8911-0a571c0b578a.png" width="500">

`livebox` is a CLI I wrote to quickly reboot my Livebox 4 as well as to see the
modem's bandwidth. It also works with Livebox 5 models. The Livebox is an
all-in-one internet router that the French ISP Orange is renting to their
customers.

You will need [curl](https://curl.se/), [yq](https://github.com/mikefarah/yq),
and [gum](https://github.com/charmbracelet/gum) to run this CLI. To install them on macOS:

```sh
brew install curl yq gum
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

Features:

```text
% livebox --help
Interact with a Livebox 4 or 5 (Orange). To authenticate, you can either use
the login command, or provide the password with --password or LIVEBOX_PASSWORD.
When using the login command, the credentials are saved in
~/.config/livebox.yml. This file has the format:

    address: 192.168.1.1
    username: admin
    password: password


Usage:
    livebox <command> [options]

Commands:
    login        Authenticate to the livebox and save the information in
                 ~/.config/livebox.yml.
    ls           List all devices known and their IPs.
    reboot       Reboots the livebox. Useful when upstream or downstream
                 bandwiths aren't great.
    phone        Show recent phone calls. Useful to report unwanted/spam calls.
    speed        Show the DSL Downstream and Upstream speeds. The 0.96 weight
                 mentioned in speed --raw is already applied.
    speedraw     Show the output of NeMo.Intf.data/getMIBs. The numbers
                 like 'downstream current rate' are given in kbit/s. Depending
                 on your link mode (vdsl, dsl), this raw number has to be
                 weighted in order to know your real downstream bandwith:
                   - dsl: the real bandwidth is DownstreamCurrRate * 0.88
                   - vdsl: the real bandwidth is DownstreamCurrRate * 0.96
                 See: http://192.168.1.1/internal/internetState/tile.js
    dsl          Show the output of NeMo.Intf.dsl0/getDSLStats.
    firewall     List firewall IPv4 settings.
    add          Add a firewall rule for IPv4.
    api         Send a raw API request. You have to provide the JSON payload
                 on stdin.

Options:
    --username   Username to use for authentication. Defaults to "admin".
                 You can also use LIVEBOX_USERNAME.
    --password   Password to use for authentication. You can also use
                 LIVEBOX_PASSWORD.
    --address    IP or hostname of the livebox. Default: "192.168.1.1". You can
                 also use LIVEBOX_ADDRESS.
    --help, -h   Show help.
    --debug, -d  Enable debug output on stderr, inluding curl's call
                 bodies and responses.

Maël Valais, 2024.
```

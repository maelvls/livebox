# livebox CLI for livebox v4

This is a CLI I wrote to quickly reboot my Livebox v4. The Livebox v4 is a
all-in-one internet router that the French ISP Orange is renting to their
customers.

Example:

```sh
livebox --password foobar reboot
```

Features:

```
% livebox --help
Interact with a Livebox 4 (Orange).

Usage:
    livebox <command> [options]

Commands:
    reboot       Reboots the livebox. Useful when upstream or downstream
                 bandwiths aren't great.
    phone        Show recent phone calls. Useful to report unwanted/spam calls.
    speed        Show the output of NeMo.Intf.data/getMIBs. The numbers
                 like 'downstream current rate' are given in kbit/s. Depending
                 on your link mode (vdsl, dsl), this raw number has to be
                 weighted in order to know your real downstream bandwith:
                   - dsl: the real bandwidth is DownstreamCurrRate * 0.88
                   - vdsl: the real bandwidth is DownstreamCurrRate * 0.96
                 See: http://192.168.1.1/internal/internetState/tile.js
    dsl          Show the output of NeMo.Intf.dsl0/getDSLStats.

Options:
    --username   Username to use for authentication. Defaults to "admin".
                 You can also use LIVEBOX_USERNAME.
    --password   Password to use for authentication. You can also use
                 LIVEBOX_PASSWORD.
    --address    IP or hostname of the livebox. Default: "". You can
                 also use LIVEBOX_ADDRESS.
    --help, -h   Show help.
    -d           Enable debug output on stderr, inluding curl's call
                 bodies and responses.

Maël Valais, 2020
```

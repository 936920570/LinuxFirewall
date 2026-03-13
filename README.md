# My Firewall (Linux Kernel Firewall + User CLI)

A lightweight Linux firewall project implemented with a kernel module and a user-space command-line tool.

## Features

- Packet filtering by:
  - source/destination IP (with mask)
  - source/destination port range
  - protocol (`TCP`, `UDP`, `ICMP`, `any`)
- Rule actions:
  - `ACCEPT`
  - `DROP`
- Optional packet logging
- Basic source NAT rule management
- Connection tracking (stateful behavior)
- Netlink-based communication between user app and kernel module

## Project Structure

- `firewall_module/`: kernel module source code
  - hooks, rules, NAT, logs, connection table, netlink handlers
- `userApp/`: user-space CLI tool (`myFW`)
- `Makefile`: build/clean/install orchestration
- `my_firewall.c`, `my_dev.c`: standalone kernel module demos/tests

## Requirements

- Linux system with kernel headers installed
- `gcc`
- `make`
- Root privileges for module load/unload (`insmod`, `rmmod`)

## Build

From repository root:

```bash
make
```

This builds:
- kernel module: `firewall_module/myfw.ko`
- user CLI: `userApp/myFW`

## Install / Load

```bash
cd firewall_module
sudo rmmod myfw 2>/dev/null || true
sudo insmod myfw.ko
```

## User CLI Usage

The CLI binary is `myFW`.

General format:

```bash
./myFW <cmd-type> <action> [args]
```

Examples:

```bash
# Show all filter rules
./myFW rule show

# Add a filter rule (interactive)
./myFW rule add

# Delete a rule by name
./myFW rule del <rule_name>

# Set default action
./myFW rule default accept
./myFW rule default drop

# Show NAT rules
./myFW nat show

# Add NAT rule (interactive)
./myFW nat add

# Delete NAT rule by sequence index
./myFW nat del <index>

# Show logs
./myFW show log [count]

# Show tracked connections
./myFW show connection
```

## Clean

```bash
make clean
```

## Notes

- This project is intended for educational and experimental use.
- Kernel APIs vary by kernel version; minor compatibility updates may be required on newer kernels.
- `firewall_module/headers/uthash.h` is a third-party dependency and keeps its original license header.

## License

This repository currently does not include a top-level LICENSE file.
Add your preferred license before publishing if needed.

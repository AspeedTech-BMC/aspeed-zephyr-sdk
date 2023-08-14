# Introduction
This repository provides fimware applications for AST1030 and AST1060, these
applications are developing on top of [Zephyr BSP](https://github.com/AspeedTech-BMC/zephyr).


# Building ASPEED-PFR firmware

```
west init -m https://github.com/AspeedTech-BMC/aspeed-zephyr-project --mr aspeed-master workspace
cd workspace
west update
```

## AST2600 DCSCM board

```
west build -b ast1060_dcscm -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 Dual Flash

```
west build -b ast1060_dual_flash -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 DCSCM board for AMD

```
west build -b ast1060_dcscm_amd -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## AST2600 Dual Flash for AMD

```
west build -b ast1060_dual_flash_amd -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

## PROT Module

```
west build -b ast1060_prot -p auto aspeed-zephyr-project/apps/aspeed-pfr
```

# Building Preload Firmware

```
west init -m https://github.com/AspeedTech-BMC/aspeed-zephyr-project --mr aspeed-master workspace
cd workspace
west update
west build -b ast1060_dcscm_dice -p auto aspeed-zephyr-project/apps/preload-fw
```

## Signing Preload Firmware

```
imgtool sign --version 1.1.1 --align 8 --header-size 1024 --slot-size 393216 --load-addr 196608 --key bootloader/mcuboot/root-rsa-2048.pem ./zephyr.bin ./zephyr.signed.bin
```

# Building DMTF/LibSPDM Emulator
This spdm emualtor will create two threads as a requester and a responder.
The requester will initiate the connection and establish a session.
After the session is esatblished, the requester will ask for measurement and heartbeat every second.

## Fetch DMTF/LibSPDM codebase
DMTF/LibSPDM doesn't support Zephyr module, so we use git submodule to libspdm.
```
git submodule update --init

```

## Building the firmware
```
west build -b ast1030_evb -p auto aspeed-zephyr-project/apps/spdm
```


# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE main.c)

# Common layer
add_subdirectory(AspeedStateMachine)
add_subdirectory(common)
add_subdirectory(include)
add_subdirectory(engineManager)
add_subdirectory(manifestProcessor)
add_subdirectory(pfr)
add_subdirectory(platform_monitor)
add_subdirectory(Smbus_mailbox)
add_subdirectory(watchdog_timer)
add_subdirectory(otp)

# Vendor specific layer
add_subdirectory_ifdef(CONFIG_INTEL_PFR intel_pfr)
add_subdirectory_ifdef(CONFIG_CERBERUS_PFR cerberus_pfr)

# Features
add_subdirectory_ifdef(CONFIG_PFR_MCTP mctp)
add_subdirectory_ifdef(CONFIG_PFR_SPDM_ATTESTATION SPDM)

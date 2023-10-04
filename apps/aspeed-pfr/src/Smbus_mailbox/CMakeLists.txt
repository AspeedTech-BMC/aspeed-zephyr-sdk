# Copyright (c) 2022 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT
target_sources(app PRIVATE Smbus_mailbox.c)
target_sources_ifdef(CONFIG_PROVISION_SHELL app PRIVATE provision_shell.c)

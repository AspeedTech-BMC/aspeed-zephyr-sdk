# Copyright (c) 2023 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

zephyr_include_directories(.)
zephyr_include_directories(include)
zephyr_include_directories(os_stub)
zephyr_include_directories(os_stub/spdm_device_secret_lib_zephyr)

target_sources(
	app PRIVATE
	main.c
	spdm_req.c
	spdm_rsp.c
	spdm_fifo.c

	os_stub/debuglib_zephyr/debuglib.c
	os_stub/malloclib/malloclib.c
	os_stub/platform_lib_zephyr/time_zephyr.c
	os_stub/platform_lib_zephyr/watchdog.c
	os_stub/rnglib/rng_zephyr.c
	os_stub/spdm_device_secret_lib_zephyr/lib.c
	os_stub/spdm_device_secret_lib_zephyr/cert.c
)

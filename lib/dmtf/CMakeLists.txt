# Copyright (c) 2023 ASPEED Technology Inc.
# SPDX-License-Identifier: MIT

if (CONFIG_DMTF_LIBSPDM)

zephyr_interface_library_named(dmtf_libspdm)

target_include_directories(dmtf_libspdm INTERFACE
	include
	libspdm/include
	libspdm/include/hal
	libspdm/os_stub
	libspdm/os_stub/include
	libspdm/os_stub/mbedtlslib/mbedtls/include
	libspdm/os_stub/cryptlib_mbedtls
)

zephyr_library()

if (CONFIG_DMTF_LIBSPDM_CONFIG_FILE)
	target_compile_definitions(dmtf_libspdm INTERFACE
		LIBSPDM_CONFIG="${CONFIG_DMTF_LIBSPDM_CONFIG_FILE}")
endif()

# spdm common library
zephyr_library_sources(
	libspdm/library/spdm_common_lib/libspdm_com_context_data.c
	libspdm/library/spdm_common_lib/libspdm_com_crypto_service.c
	libspdm/library/spdm_common_lib/libspdm_com_msg_log.c
	libspdm/library/spdm_common_lib/libspdm_com_support.c
	libspdm/library/spdm_common_lib/libspdm_com_context_data_session.c
	libspdm/library/spdm_common_lib/libspdm_com_crypto_service_session.c
	libspdm/library/spdm_common_lib/libspdm_com_opaque_data.c

	libspdm/library/spdm_crypt_lib/libspdm_crypt_aead.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_asym.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_cert.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_dhe.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_hash.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_hkdf.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_hmac.c
	libspdm/library/spdm_crypt_lib/libspdm_crypt_rng.c

	libspdm/library/spdm_requester_lib/libspdm_req_challenge.c
	libspdm/library/spdm_requester_lib/libspdm_req_common.c
	libspdm/library/spdm_requester_lib/libspdm_req_communication.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_certificate.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_challenge_auth.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_digests.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_error.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_key_update.c
	libspdm/library/spdm_requester_lib/libspdm_req_encap_request.c
	libspdm/library/spdm_requester_lib/libspdm_req_end_session.c
	libspdm/library/spdm_requester_lib/libspdm_req_finish.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_capabilities.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_certificate.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_csr.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_digests.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_measurements.c
	libspdm/library/spdm_requester_lib/libspdm_req_get_version.c
	libspdm/library/spdm_requester_lib/libspdm_req_handle_error_response.c
	libspdm/library/spdm_requester_lib/libspdm_req_heartbeat.c
	libspdm/library/spdm_requester_lib/libspdm_req_key_exchange.c
	libspdm/library/spdm_requester_lib/libspdm_req_key_update.c
	libspdm/library/spdm_requester_lib/libspdm_req_negotiate_algorithms.c
	libspdm/library/spdm_requester_lib/libspdm_req_psk_exchange.c
	libspdm/library/spdm_requester_lib/libspdm_req_psk_finish.c
	libspdm/library/spdm_requester_lib/libspdm_req_send_receive.c
	libspdm/library/spdm_requester_lib/libspdm_req_set_certificate.c

	libspdm/library/spdm_responder_lib/libspdm_rsp_algorithms.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_capabilities.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_certificate.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_challenge_auth.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_chunk_get.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_chunk_send_ack.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_common.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_communication.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_csr.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_digests.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_challenge.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_get_certificate.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_get_digests.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_key_update.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_encap_response.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_end_session.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_error.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_finish.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_handle_response_state.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_heartbeat.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_key_exchange.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_key_update.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_measurements.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_psk_exchange.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_psk_finish.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_receive_send.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_respond_if_ready.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_set_certificate.c
	libspdm/library/spdm_responder_lib/libspdm_rsp_version.c

	libspdm/library/spdm_secured_message_lib/libspdm_secmes_context_data.c
	libspdm/library/spdm_secured_message_lib/libspdm_secmes_encode_decode.c
	libspdm/library/spdm_secured_message_lib/libspdm_secmes_key_exchange.c
	libspdm/library/spdm_secured_message_lib/libspdm_secmes_session.c

	libspdm/library/spdm_transport_mctp_lib/libspdm_mctp_common.c
	libspdm/library/spdm_transport_mctp_lib/libspdm_mctp_mctp.c


	libspdm/os_stub/cryptlib_mbedtls/cipher/aead_aes_gcm.c
	libspdm/os_stub/cryptlib_mbedtls/cipher/aead_chacha20_poly1305.c
	libspdm/os_stub/cryptlib_mbedtls/cipher/aead_sm4_gcm.c
	libspdm/os_stub/cryptlib_mbedtls/der/der.c
	libspdm/os_stub/cryptlib_mbedtls/hash/sha.c
	libspdm/os_stub/cryptlib_mbedtls/hash/sha3.c
	libspdm/os_stub/cryptlib_mbedtls/hash/sm3.c
	libspdm/os_stub/cryptlib_mbedtls/hmac/hmac_sha.c
	libspdm/os_stub/cryptlib_mbedtls/hmac/hmac_sha3.c
	libspdm/os_stub/cryptlib_mbedtls/hmac/hmac_sm3.c
	libspdm/os_stub/cryptlib_mbedtls/kdf/hkdf_sha.c
	libspdm/os_stub/cryptlib_mbedtls/kdf/hkdf_sha3.c
	libspdm/os_stub/cryptlib_mbedtls/kdf/hkdf_sm3.c
	libspdm/os_stub/cryptlib_mbedtls/pem/pem.c
	libspdm/os_stub/cryptlib_mbedtls/pk/ec.c
	libspdm/os_stub/cryptlib_mbedtls/pk/ecd.c
	libspdm/os_stub/cryptlib_mbedtls/pk/dh.c
	libspdm/os_stub/cryptlib_mbedtls/pk/sm2.c
	libspdm/os_stub/cryptlib_mbedtls/pk/rsa_basic.c
	libspdm/os_stub/cryptlib_mbedtls/pk/rsa_ext.c
	libspdm/os_stub/cryptlib_mbedtls/pk/x509.c
	libspdm/os_stub/cryptlib_mbedtls/rand/rand.c
	libspdm/os_stub/cryptlib_mbedtls/sys_call/mem_allocation.c
	libspdm/os_stub/cryptlib_mbedtls/sys_call/crt_wrapper_host.c

	libspdm/os_stub/memlib/compare_mem.c
	libspdm/os_stub/memlib/copy_mem.c
	libspdm/os_stub/memlib/set_mem.c
	libspdm/os_stub/memlib/zero_mem.c

	libspdm/os_stub/spdm_crypt_ext_lib/spdm_crypt_ext.c

	libspdm/os_stub/mbedtlslib/mbedtls/library/aes.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/aesni.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/arc4.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/aria.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/asn1parse.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/asn1write.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/base64.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/bignum.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/blowfish.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/camellia.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ccm.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/certs.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/chacha20.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/chachapoly.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/cipher.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/cipher_wrap.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/cmac.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/constant_time.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ctr_drbg.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/debug.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/des.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/dhm.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ecdh.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ecdsa.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ecjpake.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ecp.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ecp_curves.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/entropy.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/entropy_poll.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/error.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/gcm.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/havege.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/hkdf.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/hmac_drbg.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/md2.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/md4.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/md5.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/md.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/memory_buffer_alloc.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/mps_reader.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/mps_trace.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/net_sockets.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/nist_kw.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/oid.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/padlock.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pem.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pk.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pkcs11.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pkcs12.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pkcs5.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pkparse.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/pk_wrap.c	
	libspdm/os_stub/mbedtlslib/mbedtls/library/pkwrite.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/platform.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/platform_util.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/poly1305.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_aead.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_cipher.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_client.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_driver_wrappers.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_ecp.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_hash.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_mac.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_rsa.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_se.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_slot_management.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_crypto_storage.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/psa_its_file.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ripemd160.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/rsa.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/rsa_internal.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/sha1.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/sha256.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/sha512.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_cache.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_ciphersuites.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_cli.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_cookie.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_msg.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_srv.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_ticket.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_tls13_keys.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/ssl_tls.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/threading.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/timing.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/version.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/version_features.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509_create.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509_crl.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509_crt.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509_csr.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509write_crt.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/x509write_csr.c
	libspdm/os_stub/mbedtlslib/mbedtls/library/xtea.c
)

zephyr_library_link_libraries(dmtf_libspdm)

endif()


#include <stdint.h>
#include <zephyr/kernel.h>

#pragma once

/* public cert*/

bool libspdm_read_responder_public_certificate_chain(
	uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
	size_t *size, void **hash, size_t *hash_size);

/*This alias cert chain is partial, from root CA to device certificate CA.*/
bool libspdm_read_responder_public_certificate_chain_alias_cert_till_dev_cert_ca(
	uint32_t base_hash_algo, uint32_t base_asym_algo, void **data,
	size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_per_slot(
	uint8_t slot_id, uint32_t base_hash_algo, uint32_t base_asym_algo,
	void **data, size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_requester_public_certificate_chain(
	uint32_t base_hash_algo, uint16_t req_base_asym_alg, void **data,
	size_t *size, void **hash, size_t *hash_size);

bool libspdm_read_responder_root_public_certificate(uint32_t base_hash_algo,
						    uint32_t base_asym_algo,
						    void **data, size_t *size,
						    void **hash,
						    size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_slot(uint8_t slot_id,
							 uint32_t base_hash_algo,
							 uint32_t base_asym_algo,
							 void **data, size_t *size,
							 void **hash,
							 size_t *hash_size);

bool libspdm_read_requester_root_public_certificate(uint32_t base_hash_algo,
						    uint16_t req_base_asym_alg,
						    void **data, size_t *size,
						    void **hash,
						    size_t *hash_size);

bool libspdm_read_responder_public_certificate_chain_by_size(
	uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
	void **data, size_t *size, void **hash,
	size_t *hash_size);

bool libspdm_read_responder_root_public_certificate_by_size(
	uint32_t base_hash_algo, uint32_t base_asym_algo, uint16_t CertId,
	void **data, size_t *size, void **hash,
	size_t *hash_size);

bool libspdm_read_responder_public_key(
	uint32_t base_asym_algo, void **data, size_t *size);

bool libspdm_read_requester_public_key(
	uint16_t req_base_asym_alg, void **data, size_t *size);


/*
* Copyright (c) 2025-2026, The PurpleI2P Project
*
* This file is part of Purple i2pd project and licensed under BSD3
*
* See full license text in LICENSE file at top of project tree
*/

#include "Log.h"
#include "PostQuantum.h"

#if OPENSSL_PQ || LIBRESSL_PQ // is 1 by default

#ifndef LIBRESSL_PQ
#	include <openssl/param_build.h>
#	include <openssl/core_names.h>
#endif

#if LIBRESSL_PQ
	#warning like you use libressl
	#include<openssl/mlkem.h>
#else 
	#warning like you use openssl
#endif

#define DEF_RANK MLKEM768_RANK

namespace i2p
{
namespace crypto
{
	MLKEMKeys::MLKEMKeys (MLKEMTypes type):
		m_Name (std::get<0>(MLKEMS[type])), m_KeyLen (std::get<1>(MLKEMS[type])),
		m_CTLen (std::get<2>(MLKEMS[type])), m_Pkey (nullptr)
	{
	}
	void MLKEMKeys::FreeKeys(void) 
	{
#ifndef LIBRESSL_PQ
		if (m_Pkey) EVP_PKEY_free (m_Pkey);
#else
		if (m_PublicKey) { MLKEM_public_key_free(m_PublicKey); m_PublicKey = nullptr; }
	    if (m_Pkey) MLKEM_private_key_free (m_Pkey);
#endif
		if (m_Pkey) m_Pkey = nullptr;
	}
	MLKEMKeys::~MLKEMKeys ()
	{
		FreeKeys();
	}

	void MLKEMKeys::GenerateKeys ()
	{
		FreeKeys();
#ifndef LIBRESSL_PQ
		m_Pkey = EVP_PKEY_Q_keygen(NULL, NULL, m_Name.c_str ());
#else
		m_Pkey = MLKEM_private_key_new(DEF_RANK);
#endif
	}

	void MLKEMKeys::GetPublicKey (uint8_t * pub) const
	{
		if (m_Pkey)
		{
			size_t len = m_KeyLen;
			#ifndef LIBRESSL_PQ
		    EVP_PKEY_get_octet_string_param (m_Pkey, OSSL_PKEY_PARAM_PUB_KEY, pub, m_KeyLen, &len);
		    #else
		    /*
		     * MLKEM_generate_key(MLKEM_private_key *private_key,
				uint8_t **out_encoded_public_key, size_t *out_encoded_public_key_len,
				uint8_t **out_optional_seed, size_t *out_optional_seed_len);
				https://github.com/libressl/openbsd/blob/8662e35dbd36d8450a6d4c7188a65c580e4b339f/src/lib/libcrypto/mlkem/mlkem.h#L125C5-L128C1
				maybe int MLKEM_public_from_private(const MLKEM_private_key *private_key,
					MLKEM_public_key *public_key);?
			*/
			{
//				auto result = MLKEM_generate_key(m_Pkey, &pub, &len, nullptr, nullptr);
//				if(result != 0) {
//					LogPrint (eLogError, "MLKEM [libressl]: can't generate public key");
					if (!m_Pkey) return;

					auto pub_key = MLKEM_public_key_new(DEF_RANK); 
					
					if (MLKEM_public_from_private(m_Pkey, pub_key) == 0)
					{
						//int MLKEM_marshal_public_key(const MLKEM_public_key *public_key, uint8_t **out,    size_t *out_len);
						MLKEM_marshal_public_key(pub_key, &pub, &len);
					}
					else
					{
						LogPrint(eLogError, "MLKEM [libressl]: can't extract public key from private");
					}					
					MLKEM_public_key_free(pub_key);
					
				}
		    #endif
		}
	}
	

	void MLKEMKeys::SetPublicKey (const uint8_t * pub)
	{
		#ifndef LIBRESSL_PQ
		if(!m_Pkey) return LogPrint(eLogError, "We are don't have private key for set public key");
		FreeKeys();
		OSSL_PARAM params[] =
		{
			OSSL_PARAM_octet_string (OSSL_PKEY_PARAM_PUB_KEY, (uint8_t *)pub, m_KeyLen),
			OSSL_PARAM_END
		};
		EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_name (NULL, m_Name.c_str (), NULL);
		if (ctx)
		{
			EVP_PKEY_fromdata_init (ctx);
			EVP_PKEY_fromdata (ctx, &m_Pkey, OSSL_KEYMGMT_SELECT_PUBLIC_KEY, params);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
		#else
			if (m_PublicKey) MLKEM_public_key_free(m_PublicKey);
			m_PublicKey = MLKEM_public_key_new(DEF_RANK);
			if (!MLKEM_parse_public_key(m_PublicKey, pub, m_KeyLen))
			{
				LogPrint(eLogError, "MLKEM: failed to parse public key");
				MLKEM_public_key_free(m_PublicKey);
				m_PublicKey = nullptr;
			}
			//LogPrint(eLogError, "MLKEM SetPublicKey [libressl] NOT IMPLEMENTED YET");
		#endif
	}

	void MLKEMKeys::Encaps (uint8_t * ciphertext, uint8_t * shared)
	{
		if (!m_Pkey) return;
		#ifndef LIBRESSL_PQ
		auto ctx = EVP_PKEY_CTX_new_from_pkey (NULL, m_Pkey, NULL);
		if (ctx)
		{
			EVP_PKEY_encapsulate_init (ctx, NULL);
			size_t len = m_CTLen, sharedLen = 32;
			EVP_PKEY_encapsulate (ctx, ciphertext, &len, shared, &sharedLen);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
		#else
		//	auto res = MLKEM_encap(
		#endif
	}

	void MLKEMKeys::Decaps (const uint8_t * ciphertext, uint8_t * shared)
	{
		if (!m_Pkey) return;
		auto ctx = EVP_PKEY_CTX_new_from_pkey (NULL, m_Pkey, NULL);
		if (ctx)
		{
			EVP_PKEY_decapsulate_init (ctx, NULL);
			size_t sharedLen = 32;
			EVP_PKEY_decapsulate (ctx, shared, &sharedLen, ciphertext, m_CTLen);
			EVP_PKEY_CTX_free (ctx);
		}
		else
			LogPrint (eLogError, "MLKEM can't create PKEY context");
	}

	std::unique_ptr<MLKEMKeys> CreateMLKEMKeys (i2p::data::CryptoKeyType type)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)MLKEMS.size ()) return nullptr;
		return std::make_unique<MLKEMKeys>((MLKEMTypes)(type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1));
	}

	static constexpr std::array NoiseIKInitMLKEMKeys =
	{
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0xb0, 0x8f, 0xb1, 0x73, 0x92, 0x66, 0xc9, 0x90, 0x45, 0x7f, 0xdd, 0xc6, 0x4e, 0x55, 0x40, 0xd8,
				0x0a, 0x37, 0x99, 0x06, 0x92, 0x2a, 0x78, 0xc4, 0xb1, 0xef, 0x86, 0x06, 0xd0, 0x15, 0x9f, 0x4d
			}, // SHA256("Noise_IKhfselg2_25519+MLKEM512_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x95, 0x8d, 0xf6, 0x6c, 0x95, 0xce, 0xa9, 0xf7, 0x42, 0xfc, 0xfa, 0x62, 0x71, 0x36, 0x1e, 0xa7,
				0xdc, 0x7a, 0xc0, 0x75, 0x01, 0xcf, 0xf9, 0xfc, 0x9f, 0xdb, 0x4c, 0x68, 0x3a, 0x53, 0x49, 0xeb
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x36, 0x03, 0x90, 0x2d, 0xf9, 0xa2, 0x2a, 0x5e, 0xc9, 0x3d, 0xdb, 0x8f, 0xa8, 0x1b, 0xdb, 0x4b,
				0xae, 0x9d, 0x93, 0x9c, 0xdf, 0xaf, 0xde, 0x55, 0x49, 0x13, 0xfe, 0x98, 0xf8, 0x4a, 0xd4, 0xbd
			}, // SHA256("Noise_IKhfselg2_25519+MLKEM768_ChaChaPoly_SHA256")
		 	std::array<uint8_t, 32>
		 	{
				0x15, 0x44, 0x89, 0xbf, 0x30, 0xf0, 0xc9, 0x77, 0x66, 0x10, 0xcb, 0xb1, 0x57, 0x3f, 0xab, 0x68,
				0x79, 0x57, 0x39, 0x57, 0x0a, 0xe7, 0xc0, 0x31, 0x8a, 0xa2, 0x96, 0xef, 0xbf, 0xa9, 0x6a, 0xbb
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x86, 0xa5, 0x36, 0x44, 0xc6, 0x12, 0xd5, 0x71, 0xa1, 0x2d, 0xd8, 0xb6, 0x0a, 0x00, 0x9f, 0x2c,
				0x1a, 0xa8, 0x7d, 0x22, 0xa4, 0xff, 0x2b, 0xcd, 0x61, 0x34, 0x97, 0x6d, 0xa1, 0x49, 0xeb, 0x4a
			}, // SHA256("Noise_IKhfselg2_25519+MLKEM1024_ChaChaPoly_SHA256")
		 	std::array<uint8_t, 32>
		 	{
				0x42, 0x0d, 0xc2, 0x1c, 0x7b, 0x18, 0x61, 0xb7, 0x4a, 0x04, 0x3d, 0xae, 0x0f, 0xdc, 0xf2, 0x71,
				0xb9, 0xba, 0x19, 0xbb, 0xbd, 0x5f, 0xd4, 0x9c, 0x3f, 0x4b, 0x01, 0xed, 0x6d, 0x13, 0x1d, 0xa2
			} // SHA256 (first)
		)
	};

	void InitNoiseIKStateMLKEM (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)NoiseIKInitMLKEMKeys.size ()) return;
		auto ind = type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1;
		state.Init (NoiseIKInitMLKEMKeys[ind].first.data(), NoiseIKInitMLKEMKeys[ind].second.data(), pub);
	}

	static constexpr std::array NoiseXKInitMLKEMKeys =
	{
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0xf9, 0x9f, 0x6c, 0x60, 0xea, 0x06, 0x78, 0x7f, 0x8d, 0xc2, 0x3f, 0xa3, 0xe9, 0xf7, 0xc0, 0xa5,
				0x34, 0x77, 0x10, 0xc1, 0x1d, 0x99, 0xe0, 0xe9, 0x9c, 0xe3, 0x90, 0x2b, 0x92, 0x32, 0x07, 0x20
			}, // SHA256("Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x6a, 0xc4, 0x2c, 0xd8, 0x31, 0xeb, 0xd3, 0x0c, 0xdf, 0x90, 0x2e, 0x67, 0xf4, 0x66, 0x39, 0xab,
				0x85, 0xcf, 0xac, 0x0f, 0x77, 0xba, 0x79, 0x58, 0x61, 0xe9, 0x56, 0x97, 0x44, 0x99, 0xad, 0xe1
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0xb9, 0xc3, 0x44, 0x56, 0x11, 0xcc, 0x80, 0xec, 0xca, 0x15, 0xde, 0x37, 0xa4, 0x1a, 0xb6, 0xc6,
				0xfb, 0x59, 0xdb, 0x83, 0xeb, 0x1e, 0x9d, 0x7e, 0x27, 0x63, 0xa8, 0xa5, 0x34, 0xec, 0x53, 0xd1
			}, // SHA256("Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x0b, 0xcd, 0x38, 0xaf, 0xcf, 0xb7, 0xaa, 0xeb, 0x25, 0x73, 0xb8, 0x4f, 0x74, 0x83, 0x02, 0x94,
				0x8b, 0x53, 0xf5, 0x42, 0xce, 0x3f, 0x23, 0xdc, 0xcc, 0x9a, 0xe9, 0xb0, 0x21, 0xab, 0x48, 0xff
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x97, 0xe6, 0x8d, 0x27, 0x49, 0x41, 0x50, 0xea, 0x80, 0x54, 0x8e, 0x73, 0x04, 0x45, 0x3f, 0x61,
				0x29, 0xbc, 0x07, 0x8b, 0x14, 0x05, 0x13, 0xbe, 0x9a, 0x55, 0xb2, 0x07, 0xa2, 0xda, 0x37, 0x0c
			}, // SHA256("Noise_XKhfsaesobfse+hs2+hs3_25519+MLKEM1024_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0x59, 0x50, 0x1a, 0x59, 0x87, 0x82, 0x65, 0x55, 0x58, 0x09, 0x9b, 0xec, 0xab, 0x2a, 0x64, 0x1d,
				0xf1, 0x7b, 0xca, 0xe7, 0xb3, 0x5d, 0x6d, 0xa7, 0x8c, 0x6e, 0x79, 0x7e, 0xab, 0xf3, 0x57, 0x3f
			} // SHA256 (first)
		)
	};

	void InitNoiseXKStateMLKEM (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)NoiseXKInitMLKEMKeys.size ()) return;
		auto ind = type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1;
		state.Init (NoiseXKInitMLKEMKeys[ind].first.data(), NoiseXKInitMLKEMKeys[ind].second.data(), pub);
	}

	static constexpr std::array NoiseXKInitMLKEMKeys1 =
	{
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x16, 0x22, 0x45, 0x4d, 0xbe, 0xa3, 0xf7, 0x7b, 0xcf, 0x5a, 0x0b, 0x60, 0xf8, 0x56, 0xe0, 0x54,
				0xa6, 0x79, 0x72, 0x74, 0x2a, 0xb7, 0x1a, 0xdf, 0x39, 0x38, 0x7d, 0x35, 0xf8, 0x90, 0x41, 0x68
			}, // SHA256("Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM512_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0xb1, 0x84, 0xaf, 0x89, 0xb5, 0xd2, 0x7f, 0xbd, 0xa4, 0x62, 0xbe, 0x35, 0xa4, 0xc0, 0x17, 0x77,
				0xfb, 0x70, 0xc7, 0x39, 0x28, 0x72, 0xcf, 0x74, 0x4a, 0xbf, 0x3c, 0xc5, 0xb8, 0x6c, 0xaf, 0xcf
			} // SHA256 (first)
		),
		std::make_pair
		(
			std::array<uint8_t, 32>
		 	{
				0x06, 0x45, 0x8d, 0x7f, 0x4a, 0x0e, 0x53, 0xd3, 0x7b, 0xdb, 0xbb, 0x74, 0x77, 0x99, 0xa1, 0x04,
				0xc7, 0x52, 0x00, 0x0b, 0xe0, 0xd1, 0x2a, 0x83, 0x03, 0x7b, 0xe3, 0xd1, 0xdb, 0x77, 0xf2, 0x90
			}, // SHA256("Noise_XKhfschaobfse+hs1+hs2+hs3_25519+MLKEM768_ChaChaPoly_SHA256")
			std::array<uint8_t, 32>
		 	{
				0xd6, 0xae, 0x20, 0x15, 0x44, 0x5f, 0x61, 0xa5, 0xa7, 0xe2, 0x87, 0xcf, 0x64, 0xe0, 0x0c, 0xcc,
				0x97, 0xeb, 0xea, 0x1c, 0x5d, 0xd0, 0x8c, 0x26, 0x34, 0x32, 0x06, 0xf5, 0x5e, 0x28, 0xad, 0x12
			} // SHA256 (first)
		)
		// no ML-KEM-1024
	};

	void InitNoiseXKStateMLKEM1 (NoiseSymmetricState& state, i2p::data::CryptoKeyType type, const uint8_t * pub)
	{
		if (type <= i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD ||
		    type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD > (int)NoiseXKInitMLKEMKeys1.size ()) return;
		auto ind = type - i2p::data::CRYPTO_KEY_TYPE_ECIES_X25519_AEAD - 1;
		state.Init (NoiseXKInitMLKEMKeys1[ind].first.data(), NoiseXKInitMLKEMKeys1[ind].second.data(), pub);
	}
}
}
#else
	#warning You are compile without PQ support
#endif

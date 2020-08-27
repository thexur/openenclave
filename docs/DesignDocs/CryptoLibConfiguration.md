# Configuration Parity Analysis between MbedTLS and OpenSSL Crypto Libraries

This document compares the build-time configuration of MbedTLS, which
has been extenstively reviewed when the library was ported to OE,
against that of OpenSSL, which OE recently starts to support. The goal of this
analysis is to ensure the parity behween the two. For certain configurations
that cannot achieve parity, the analysis also tries to reason out the gap.

*Note:* The following table only lists the options that are revelant to
the cryptographic algorithms. The table uses *CONFIG* or *!CONFIG* to indicate the
corresponding configuration is set or not.

## Parity analysis based on MbedlTLS

MbedTLS | OpenSSL | Comment
:---|:---|:---|
MBEDTLS_HAVE_ASM | !OPENSSL_NO_ASM | OpenSSL enables ASM by default (MD5_ASM, SHA1_ASM, RMD160_ASM, SHA256_ASM, SHA512_ASM, AES_ASM).  |
MBEDTLS_HAVE_SSE2 | OPENSSL_IA32_SSE2 | Enabled since SGX chips should all support SSE2. OpenSSL enables sse2 by default. |
MBEDTLS_CIPHER_MODE_CBC | N/A | OpenSSL supports CBC mode by default. |
!MBEDTLS_CIPHER_MODE_CFB | N/A | OpenSSL supports CFB mode by default. |
MBEDTLS_CIPHER_MODE_CTR | N/A | OpenSSL supports CTR mode by default. |
MBEDTLS_CIPHER_MODE_OFB | N/A | OpenSSL supports OFB mode by default. |
MBEDTLS_CIPHER_MODE_XTS | N/A | OpenSSL supports XTS mode by default. |
!MBEDTLS_CIPHER_NULL_CIPHER | N/A | OpenSSL does not have equivalent option. Mbed disables this option along with !MBEDTLS_ENABLE_WEAK_CIPHERSUITES. |
!MBEDTLS_ENABLE_WEAK_CIPHERSUITES | OPENSSL_NO_WEAK_SSL_CIPHERS | Both implementations disable a similar set of ciphersuites. Require further investigation to check the difference. |
MBEDTLS_CIPHER_PADDING_PKCS7 | N/A | - |
MBEDTLS_CIPHER_PADDING_ONE_AND_ZEROS | N/A | - |
MBEDTLS_CIPHER_PADDING_ZEROS_AND_LEN | N/A | - |
MBEDTLS_CIPHER_PADDING_ZEROS | N/A | - |
MBEDTLS_REMOVE_ARC4_CIPHERSUITES | OPENSSL_NO_WEAK_SSL_CIPHERS | The option prevents the use of RC4 in the SSL ciphersuite but still supports the algorithm in the crypto library. OpenSSL prevents the use of RC4 as part of OPENSSL_NO_WEAK_SSL_CIPHERS option. |
MBEDTLS_REMOVE_3DES_CIPHERSUITES | OPENSSL_NO_WEAK_SSL_CIPHERS | The option prevents the use of 3DES in the SSL ciphersuite but still supports the algorithm in the crypto library. OpenSSL prevents the use of 3DES as part of OPENSSL_NO_WEAK_SSL_CIPHERS option. |
!MBEDTLS_ECP_DP_SECP192R1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
!MBEDTLS_ECP_DP_SECP224R1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
MBEDTLS_ECP_DP_SECP256R1_ENABLED | N/A | p256 matches NSA's suite B. OpenSSL supports SECP 256r1 (i.e., X9.62 prime256v1) by default.  |
MBEDTLS_ECP_DP_SECP384R1_ENABLED | N/A | p384 matches NSA's suite B. OpenSSL supports SECP 384r1 by default. |
MBEDTLS_ECP_DP_SECP521R1_ENABLED | N/A | p521 matches NSA's suite B. OpenSSL supports SPEC 521r1 by default. |
!MBEDTLS_ECP_DP_SECP192K1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
!MBEDTLS_ECP_DP_SECP224K1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
MBEDTLS_ECP_DP_SECP256K1_ENABLED | N/A | p256k1 is used by bitcoin. OpenSSL supports SECP256k1 by default. |
!MBEDTLS_ECP_DP_BP256R1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
!MBEDTLS_ECP_DP_BP384R1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
!MBEDTLS_ECP_DP_BP512R1_ENABLED | N/A | Cannot be disabled on OpenSSL. |
MBEDTLS_ECP_DP_CURVE25519_ENABLED | N/A | OpenSSL supports curve 25519 by default. |
MBEDTLS_ECP_DP_CURVE448_ENABLED | N/A | OpenSSL supports curve 448 by default. |
MBEDTLS_ECP_NIST_OPTIM | N/A | No equivalent option in OpenSSL. |
!MBEDTLS_ECP_RESTARTABLE | N/A | No equivalent option in OpenSSL. |
MBEDTLS_ECDSA_DETERMINISTIC | N/A | No equivalent option in OpenSSL. |
!MBEDTLS_KEY_EXCHANGE_PSK_ENABLED | OPENSSL_NO_PSK | Disable pre-shared keys in enclaves until we have a use case. Basic PSK has no perfect forward secrecy, not recommended for future use. Disable PSK on OpenSSL with the no-psk configuration. |
!MBEDTLS_KEY_EXCHANGE_DHE_PSK_ENABLED | OPENSSL_NO_PSK | Disable pre-shared keys in enclaves until we have a use case. Disable PSK on OpenSSL with the no-psk configuration. |
!MBEDTLS_KEY_EXCHANGE_ECDHE_PSK_ENABLED | OPENSSL_NO_PSK | Disable pre-shared keys in enclaves until we have a use case. Disable PSK on OpenSSL with the no-psk configuration. |
!MBEDTLS_KEY_EXCHANGE_RSA_PSK_ENABLED | OPENSSL_NO_PSK | Disable pre-shared keys in enclaves until we have a use case. RSA PSK has no perfect forward secrecy, not recommended for future use. Disable PSK on OpenSSL with the no-psk configuration. |
!MBEDTLS_KEY_EXCHANGE_RSA_ENABLED | N/A | Deprecated in v0.7, developers should consider ECDHE key exchange instead for forward secrecy. No equivalent option in OpenSSL. The following ciphersuites are supported by OpenSSL: `RSA_WITH_AES_256_GCM_SHA384`, `RSA_WITH_AES_256_CBC_SHA`, `RSA_WITH_CAMELLIA_256_CBC_SHA256`, `RSA_WITH_CAMELLIA_256_CBC_SHA`, `RSA_WITH_AES_128_GCM_SHA256`, `RSA_WITH_AES_128_CBC_SHA`, `RSA_WITH_CAMELLIA_128_CBC_SHA256`, and `RSA_WITH_CAMELLIA_128_CBC_SHA`. |
!MBEDTLS_KEY_EXCHANGE_DHE_RSA_ENABLED | N/A | Not supported in favor of ECDHE for performance. No equivalent option in OpenSSL. The following ciphersuites are supported by OpenSSL: `DHE_RSA_WITH_AES_256_GCM_SHA384`, `DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256`, `DHE_RSA_WITH_CAMELLIA_256_CBC_SHA`, `DHE_RSA_WITH_AES_128_GCM_SHA256`, `DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256`, and `DHE_RSA_WITH_CAMELLIA_128_CBC_SHA`. |
MBEDTLS_KEY_EXCHANGE_ECDHE_RSA_ENABLED | N/A | OpenSSL supports ECDHE-RSA based ciphersuites by default. No equivalent option in OpenSSL. |
MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED | N/A | OpenSSL supports ECDHE-ECDSA based ciphersuites by default. No equivalent option in OpenSSL. |
!MBEDTLS_KEY_EXCHANGE_ECDH_ECDSA_ENABLED | N/A | Drop uncommon protocol to minimize TCB. No equivalent option in OpenSSL. |
!MBEDTLS_KEY_EXCHANGE_ECDH_RSA_ENABLED | N/A | Drop uncommon protocol to minimize TCB. No equivalent option in OpenSSL. |
!MBEDTLS_KEY_EXCHANGE_ECJPAKE_ENABLED | N/A | No equivalent option in OpenSSL. |
!MBEDTLS_PK_PARSE_EC_EXTENDED | N/A | Drop support for non-standard EC Curve. No equivalent option in OpenSSL. |
MBEDTLS_PKCS1_V15 | N/A | - |
MBEDTLS_PKCS1_V21 | N/A | - |
!MBEDTLS_RSA_NO_CRT | N/A | Cannot be disabled on OpenSSL. |
MBEDTLS_AESNI_C | AES_ASM | - |
MBEDTLS_AES_C | N/A | - |
!MBEDTLS_ARC4_C | OPENSSL_NO_RC4 | Disable on OpenSSL with the no-rc4 configuration. |
MBEDTLS_BIGNUM_C | N/A | - |
!MBEDTLS_BLOWFISH_C | OPENSSL_NO_BF | Drop support for uncommon cipher. Disable on OpenSSL with the no-bf configuration. |
!MBEDTLS_CAMELLIA_C | OPENSSL_NO_CAMELLIA | Drop support for uncommon cipher. Disable on OpenSSL with the no-camellia configuration. |
!MBEDTLS_ARIA_C | OPENSSL_NO_ARIA | Drop support for uncommon cipher. Disable on OpenSSL with the no-aria configuration. |
MBEDTLS_CCM_C | N/A | - |
!MBEDTLS_CHACHA20_C | OPENSSL_NO_CHACHA | Disable less common cipher until there's a demand for it. Disable on OpenSSL with the no-chacha configuration. |
!MBEDTLS_CHACHAPOLY_C | OPENSSL_NO_CHACHA | Disable less common cipher until there's a demand for it. Disable on OpenSSL with the no-chacha configuration. |
MBEDTLS_CMAC_C | !OPENSSL_NO_CMAC | Enable as it's broadly used, allowed by NIST SP standards. |
MBEDTLS_DES_C | !OPENSSL_NO_DES | Enable for backward compatibility as some protocols use it (e.g. payment industry protocols). |
MBEDTLS_ECDH_C | !OPENSSL_NO_EC | - |
MBEDTLS_ECDSA_C | !OPENSSL_NO_EC | - |
MBEDTLS_ECJPAKE_C | N/A | OpenSSL does not support JPAKE (removed in v1.1.0). |
MBEDTLS_ECP_C | N/A | - |
MBEDTLS_GCM_C | N/A | - |
!MBEDTLS_HAVEGE_C | N/A | Mbed-specific option. |
MBEDTLS_HKDF_C | N/A | OpenSSL supports HKDF by default (started from v1.1.0). |
MBEDTLS_HMAC_DRBG_C | N/A | Mbed-specific option. |
!MBEDTLS_NIST_KW_C | N/A | No equivalent option in OpenSSL. |
MBEDTLS_MD_C | N/A | No equivalent option in OpenSSL. |
!MBEDTLS_MD2_C | OPENSSL_NO_MD2 | Disable on OpenSSL with the no-md2 configuration. |
!MBEDTLS_MD4_C | OPENSSL_NO_MD4 | Disable on OpenSSL with the no-md4 configuration. |
MBEDTLS_MD5_C | !OPENSSL_NO_MD5 | Enable for backward compatibility. The algorithm is still commonly used. |
MBEDTLS_PKCS5_C | N/A | - |
!MBEDTLS_PKCS11_C | N/A | - |
MBEDTLS_PKCS12_C | N/A | - |
!MBEDTLS_POLY1305_C | OPENSSL_NO_POLY1305 | Drop the uncommon hash algorithm to minimize TCB. Disable on OpenSSL with the no-poly1305 configuration.
!MBEDTLS_RIPEMD160_C | OPENSSL_NO_RMD160 | Drop the uncommon hash algorithm to minimize TCB. Disable on OpenSSL with the no-rmd160 configuration. |
MBEDTLS_RSA_C | !OPENSSL_NO_RSA | - |
MBEDTLS_SHA1_C | N/A | OpenSSL supports SHA1 by default. |
MBEDTLS_SHA256_C | N/A | OpenSSL supports SHA256 by default. |
MBEDTLS_SHA512_C | N/A | OpenSSL supports SHA512 by default. |
!MBEDTLS_XTEA_C | N/A | No equivalent option in OpenSSL. |

## OpenSSL-specific Configuration

OpenSSL | Comment
|:---|:---|
OPENSSL_NO_BLAKE2 | Blake2 hash is not supported by MbedTLS. Disable on OpenSSL with the no-blake2 configuration to minimize TCB. |
OPENSSL_NO_CAST | CAST5 block cipher is not supported by MbedTLS. Disable on OpenSSL with the no-cast configuration to minimize TCB. |
OPENSSL_NO_GOST | Russian GOST crypto engine is not supported by mbedTLS. Require dynamic loading and therefore not supported by the OE. Disable on OpenSSL with the no-gost configuration. |
OPENSSL_NO_MDC2 | Modification Detection Code 2 is not supported by mbedTLS. Disable on OpenSSL with no-mdc2 configuration to minimize TCB. |
OPENSSL_NO_WHIRLPOOL | Whirlpool hash is not suppored by MbedTLS. Disable on OpenSSL with the no-whirlpool configuration to minimize TCB. |
OPNESSL_NO_IDEA | IDEA block cipher is not supported by MbedTLS. Disable on OpenSSL with the no-idea configuration to minimize TCB. |
OPENSSL_NO_SEED | SEED ciphersuites (RFC 4162) are not supported by MbedTLS. Disable on OpenSSL with the no-seed configuration to minimize TCB. |
OPENSSL_NO_SCRYPT | The scrypt KDF is not supported by MbedTLS. Disable on OpenSSL with the no-scrypt configuration to minimize TCB. |
OPENSSL_NO_SM2 | Chinese cryptographic algorithm(s) are not supported by MbedTLS. Disable on OpenSSL with the no-sm2 configuration. |
OPENSSL_NO_SM3 | Chinese cryptographic algorithm(s) are not supported by MbedTLS. Disable on OpenSSL with the no-sm3 configuration. |
OPENSSL_NO_SM4 | Chinese cryptographic algorithm(s) are not supported by MbedTLS. Disable on OpenSSL with the no-sm4 configuration. |
OPENSSL_NO_SRP | Secure remote password (SRP) is not supported by MbedTLS. Disable on OpenSSL with the no-srp configuration. |
OPENSSL_NO_SIPHASH | SipHash is not supported by MbedTLS. Disable on OpenSSL with the no-siphash configuration to minimize TCB. |

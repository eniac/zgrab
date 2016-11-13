package ike

import (
    "crypto/rand"
    "io"
    "strings"
    "errors"
)

func uint16ToBytes(num uint16) []byte {
    return []byte{uint8(num >> 8), uint8(num)}
}

func (c *Config) MakeBASELINE() {
    if c.Version == VersionIKEv1 {
        c.ExchangeType = IDENTITY_PROTECTION_V1 // main mode
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                // AES-CBC-128, SHA1, DH_1024, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_1024_S160, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_S160_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_2048_S224, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_S224_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_2048_S256, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_S256_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_256_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1),},
                    },
                },
                // AES-CBC-256, SHA1, DH_1024
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // AES-CBC-256, SHA1,  DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-256, SHA1, DH_256_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1),},
                    },
                },
                // 1-DES, MD5, DH_1024, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // 3-DES, MD5, DH_1024, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(MD5_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // 3-DES, SHA1, DH_1024, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // 3-DES, SHA1, DH_1024, RSA_SIGNATURES
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // AES-CBC-256, SHA2_256,  DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-256, SHA2_256, DH_2048, RSA_SIGNATURES
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
            },},
        }
    } else {
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128),},}},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2,},
                },
            },
            {ProposalNum: 2, Transforms: []TransformConfig {
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_1024_S160_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S224_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_2048_S256_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2,},
                },
            },
        }
    }
}

func (c *Config) MakeFORTIGATE() {
    if c.Version == VersionIKEv1 {
        c.ExchangeType = IDENTITY_PROTECTION_V1 // main mode
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                // Send these ciphersuites first, since the attack is more efficient with smaller groups:

                // 3-DES, SHA1, DH_768, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_768, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1),},
                    },
                },
                // 3-DES, SHA1, DH_1024, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_1024, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },

                // Default ciphersuites:

                // 3-DES, SHA1, DH_1536, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_1536, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },

                // Additional supported ciphersuites:

                // 3-DES, SHA1, DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-256, SHA2-256, DH_1536, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // AES-CBC-256, SHA2-512, DH_1536, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // AES-CBC-256, SHA2-256, DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-256, SHA2-512, DH_2048, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },

                // Try them all with RSA signatures instead of PSK
                // 3-DES, SHA1, DH_768, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_768, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_768_V1),},
                    },
                },
                // 3-DES, SHA1, DH_1024, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_1024, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1024_V1),},
                    },
                },
                // 3-DES, SHA1, DH_1536, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_1536, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // 3-DES, SHA1, DH_2048, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_3DES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_2048, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-256, SHA2-256, DH_1536, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // AES-CBC-256, SHA2-512, DH_1536, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_1536_V1),},
                    },
                },
                // AES-CBC-256, SHA2-256, DH_2048, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_256_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
                // AES-CBC-256, SHA2-512, DH_2048, RSASignatures
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA2_512_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(RSA_SIGNATURES_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_2048_V1),},
                    },
                },
            },},
        }
    } else {
        panic("FORTIGATE_V2 not implemented")
    }
}

func (c *Config) MakeECDH_BASELINE() {
    if c.Version == VersionIKEv1 {
        c.ExchangeType = IDENTITY_PROTECTION_V1 // main mode
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                // AES-CBC-128, SHA1, DH_224_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_ECP_V1),},
                    },
                },
                // AES-CBC-224, SHA1, DH_224_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(224),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_ECP_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_256_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1),},
                    },
                },
                // AES-CBC-256, SHA1, DH_256_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_ECP_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_384_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_384_ECP_V1),},
                    },
                },
                // AES-CBC-256, SHA1, DH_384_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_384_ECP_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_521_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_521_ECP_V1),},
                    },
                },
                // AES-CBC-256, SHA1, DH_521_ECP, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_521_ECP_V1),},
                    },
                },
                // AES-CBC-128, SHA1, DH_256_BRAINPOOL, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_256_BRAINPOOL_V1),},
                    },
                },
                // AES-CBC-256, SHA1, DH_256_BRAINPOOL, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(DH_224_BRAINPOOL_V1),},
                    },
                },
            },},
        }
    } else {
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128),},}},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2,},
                },
            },
            {ProposalNum: 2, Transforms: []TransformConfig {
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_224_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_384_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_521_ECP_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: DH_256_BRAINPOOL_V2,},
                },
            },
        }
    }
}

func (c *Config) MakeSINGLE_GROUP() {
    if c.Version == VersionIKEv1 {
        c.ExchangeType = IDENTITY_PROTECTION_V1 // main mode
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                // AES-CBC-128, SHA1, <group>, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(128),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(c.DhGroup),},
                    },
                },
                // AES-CBC-256, SHA1, <group>, PSK
                {IdV1: KEY_IKE_V1, Attributes: []AttributeConfig {
                    {Type: KEY_LENGTH_V1, Value: uint16ToBytes(256),},
                    {Type: ENCRYPTION_ALGORITHM_V1, Value: uint16ToBytes(ENCR_AES_CBC_V1),},
                    {Type: HASH_ALGORITHM_V1, Value: uint16ToBytes(SHA_V1),},
                    {Type: AUTHENTICATION_METHOD_V1, Value: uint16ToBytes(PRE_SHARED_KEY_V1),},
                    {Type: GROUP_DESCRIPTION_V1, Value: uint16ToBytes(c.DhGroup),},
                    },
                },
            },},
        }
    } else {
        c.Proposals = []ProposalConfig {
            {ProposalNum: 1, Transforms: []TransformConfig {
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_GCM_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128),},}},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_NONE_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DhGroup,},
                },
            },
            {ProposalNum: 2, Transforms: []TransformConfig {
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(256),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(192),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_AES_CBC_V2, Attributes: []AttributeConfig {{Type: KEY_LENGTH_V2, Value: uint16ToBytes(128),},}},
                {Type: ENCRYPTION_ALGORITHM_V2, Id: ENCR_3DES_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_512_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_384_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA2_256_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_SHA1_V2,},
                {Type: PSEUDORANDOM_FUNCTION_V2, Id: PRF_HMAC_MD5_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_512_256_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_384_192_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA2_256_128_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_SHA1_96_V2,},
                {Type: INTEGRITY_ALGORITHM_V2, Id: AUTH_HMAC_MD5_96_V2,},
                {Type: DIFFIE_HELLMAN_GROUP_V2, Id: c.DhGroup,},
                },
            },
        }
    }
}

func (c *Config) MakeConfig(configString string, ikeVersion string) (err error) {
    configString = strings.ToUpper(configString)
    if ikeVersion == "2" {
        c.Version = VersionIKEv2
    } else {
        c.Version = VersionIKEv1
    }
    // V1 and V2 group numbers are the same for the groups that both support
    switch configString {
    case "", "BASELINE":
        c.DhGroup = DH_1024_V1
        c.MakeBASELINE()
    case "FORTIGATE":
        c.DhGroup = DH_1536_V1
        c.MakeFORTIGATE()
    case "1024S160":
        c.DhGroup = DH_1024_S160_V1
        c.MakeSINGLE_GROUP()
    case "2048S224":
        c.DhGroup = DH_2048_S224_V1
        c.MakeSINGLE_GROUP()
    case "2048S256":
        c.DhGroup = DH_2048_S256_V1
        c.MakeSINGLE_GROUP()

    // check if host validates subgroup order
    // 1
    case "1024S160_1":
        c.DhGroup = DH_1024_S160_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = make([]byte, 128)
        c.KexValue[127] = 0x01
    case "2048S224_1":
        c.DhGroup = DH_2048_S224_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = make([]byte, 256)
        c.KexValue[255] = 0x01
    case "2048S256_1":
        c.DhGroup = DH_2048_S256_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = make([]byte, 256)
        c.KexValue[255] = 0x01
    // p-1
    case "1024S160_M1":
        c.DhGroup = DH_1024_S160_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = append([]byte{}, KEX_DH_1024_S160_M1...)
    case "2048S224_M1":
        c.DhGroup = DH_2048_S224_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = append([]byte{}, KEX_DH_2048_S224_M1...)
    case "2048S256_M1":
        c.DhGroup = DH_2048_S256_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = append([]byte{}, KEX_DH_2048_S256_M1...)
    // 0
    case "1024S160_0":
        c.DhGroup = DH_1024_S160_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = make([]byte, 128)
    case "2048S224_0":
        c.DhGroup = DH_2048_S224_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = make([]byte, 256)
    case "2048S256_0":
        c.DhGroup = DH_2048_S256_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = make([]byte, 256)
    // subgroup of order 7
    case "1024S160_S7":
        c.DhGroup = DH_1024_S160_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = append([]byte{}, KEX_DH_1024_S160_S7...)
    // subgroup of order 3
    case "2048S224_S3":
        c.DhGroup = DH_2048_S224_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = append([]byte{}, KEX_DH_2048_S224_S3...)
    // subgroup of order 7
    case "2048S256_S7":
        c.DhGroup = DH_2048_S256_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = append([]byte{}, KEX_DH_2048_S256_S7...)

    // elliptic curve configs
    // 
    case "ECDH_BASELINE":
        c.DhGroup = DH_256_ECP_V1
        c.MakeECDH_BASELINE()
    case "256_ECP":
        c.DhGroup = DH_256_ECP_V1
        c.MakeSINGLE_GROUP()
    case "256_ECP_INVALID_S5":
        c.DhGroup = DH_256_ECP_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = KEX_256_ECP_INVALID_S5
    case "256_ECP_TWIST_S5":
        c.DhGroup = DH_256_ECP_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = KEX_256_ECP_INVALID_S5
    case "224_ECP":
        c.DhGroup = DH_224_ECP_V1
        c.MakeSINGLE_GROUP()
    case "224_ECP_INVALID_S13":
        c.DhGroup = DH_224_ECP_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = KEX_224_ECP_INVALID_S13
    case "224_ECP_TWIST_S11":
        c.DhGroup = DH_224_ECP_V1
        c.MakeSINGLE_GROUP()
        c.KexValue = KEX_224_ECP_TWIST_S11
    case "384_ECP":
        c.DhGroup = DH_384_ECP_V1
        c.MakeSINGLE_GROUP()
    case "521_ECP":
        c.DhGroup = DH_521_ECP_V1
        c.MakeSINGLE_GROUP()
    case "256_BRAINPOOL":
        c.DhGroup = DH_256_BRAINPOOL_V1
        c.MakeSINGLE_GROUP()
    // Not yet standardized as of Nov. 2016: https://tools.ietf.org/html/draft-ietf-ipsecme-safecurves-05#section-2
    //case "CURVE25519":
    //    c.DhGroup = DH_CURVE25519_V2
    //    c.MakeSINGLE_GROUP()
    default:
        err = errors.New("unrecognized ike-config")
    }
    if c.DhGroup == 0 {
        err = errors.New("error creating ike-config")
    }
    return
}

type Config struct {
    Version                   uint16            `json:"version"`
	random                    io.Reader

    ExchangeType              uint8             `json:"exchange_type,omitempty"`
    DhGroup                   uint16            `json:"dh_group"`
    KexValue                  []byte            `json:"kex_value,omitempty"`
    Proposals                 []ProposalConfig  `json:"proposals"`
}

type ProposalConfig struct {
    ProposalNum         uint8                   `json:"proposal_num"`
    Transforms          []TransformConfig       `json:"transforms"`
}

type TransformConfig struct {
    Type                uint8                   `json:"type_v2,omitempty"`
    Id                  uint16                  `json:"id_v2,omitempty"`
    TransformNum        uint8                   `json:"transform#,omitempty"`
    IdV1                uint8                   `json:"id_v1,omitempty"`
    Attributes          []AttributeConfig       `json:"attributes,omitempty"`
}

type AttributeConfig struct {
    Type                uint16                  `json:"type"`
    Value               []byte                  `json:"value"`
}

func (c *Config) getRandom() io.Reader {
	if c.random != nil {
		return c.random
	}
	return rand.Reader
}


#include <logging/log.h>
#include <random/rand32.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tcti_zephyr.h>
#include <tss2/tss2_esys.h>

// Loglevel of main function
LOG_MODULE_REGISTER(tpm2, LOG_LEVEL_DBG);

// Glue TPM-Test Cases to Zephyr Environment
#define LOG_ERROR(...) LOG_ERR(__VA_ARGS__)
#define LOG_INFO(...)  LOG_INF(__VA_ARGS__)
#define LOGBLOB_DEBUG(...) ;
#define goto_if_error(r, m, d)               \
          if(r != TPM2_RC_SUCCESS) {         \
            LOG_ERR("Line %i: "m, __LINE__); \
            goto d;                          \
          }

// Glue mbedTLS entropy source to K64 RNG (nxp,kinetis-rnga)
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen ) {
    (void)data;
    *olen = 0;

    if(sys_csrand_get(output, len) != 0) {
      return -1;
    }

    *olen = len;
    return 0;
}

//=== copied from tpm2-tss/test/integration/esys-get-random.int.c =============
int
test_esys_get_random(ESYS_CONTEXT * esys_context)
{

    TSS2_RC r;

    TPM2B_DIGEST *randomBytes;
    r = Esys_GetRandom(esys_context, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                       48, &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom FAILED! Response Code : 0x%x", r);
        goto error;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    Esys_Free(randomBytes);

    LOG_INFO("GetRandom Test Passed!");

    ESYS_TR session = ESYS_TR_NONE;
    const TPMT_SYM_DEF symmetric = {
        .algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128},
        .mode = {.aes = TPM2_ALG_CFB}
    };

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

      r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

      r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

      r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

      r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              NULL,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("Esys_StartAuthSession FAILED! Response Code : 0x%x", r);
        goto error;
    }

    r = Esys_TRSess_SetAttributes(esys_context, session, TPMA_SESSION_AUDIT,
                                  TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_AUDIT);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("SetAttributes on session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    r = Esys_GetRandom(esys_context, session, ESYS_TR_NONE, ESYS_TR_NONE, 48,
                       &randomBytes);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("GetRandom with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    LOGBLOB_DEBUG(&randomBytes->buffer[0], randomBytes->size,
                  "Randoms (count=%i):", randomBytes->size);
    free(randomBytes);

    LOG_INFO("GetRandom with session Test Passed!");

    //r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext with session FAILED! Response Code : 0x%x", r);
        goto error_cleansession;
    }

    return EXIT_SUCCESS;

 error_cleansession:
    r = Esys_FlushContext(esys_context, session);
    if (r != TPM2_RC_SUCCESS) {
        LOG_ERROR("FlushContext FAILED! Response Code : 0x%x", r);
    }
 error:
    return EXIT_FAILURE;
}

//=== copied from tpm2-tss/test/esys-rsa-encrypt-decrypt.int.c ================
int
test_esys_rsa_encrypt_decrypt(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_PUBLIC_KEY_RSA *cipher = NULL;
    TPM2B_PUBLIC_KEY_RSA *plain2 = NULL;
    TPM2B_DATA * null_data = NULL;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0},
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL},
                 .scheme = { .scheme = TPM2_ALG_RSAES },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };

    LOG_INFO("RSA key will be created.");

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    for (int mode = 0; mode <= 2; mode++) {

        if (mode == 0) {
            inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_NULL;
        } else if (mode == 1) {
            inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_RSAES;
        } else if (mode == 2) {
            inPublic.publicArea.parameters.rsaDetail.scheme.scheme =
                TPM2_ALG_OAEP;
            inPublic.publicArea.parameters.rsaDetail.scheme.details.oaep.
                hashAlg = TPM2_ALG_SHA1;
        }

        r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                               ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                               &inPublic, &outsideInfo, &creationPCR,
                               &primaryHandle, &outPublic, &creationData,
                               &creationHash, &creationTicket);
        goto_if_error(r, "Error esys create primary", error);
        Esys_Free(outPublic);
        Esys_Free(creationData);
        Esys_Free(creationHash);
        Esys_Free(creationTicket);

        r = Esys_TR_SetAuth(esys_context, primaryHandle,
                            &authValuePrimary);
        goto_if_error(r, "Error: TR_SetAuth", error);

        size_t plain_size = 3;
        TPM2B_PUBLIC_KEY_RSA plain = {.size = plain_size,.buffer = {1, 2, 3}
        };
        TPMT_RSA_DECRYPT scheme;

        if (mode == 0) {
            scheme.scheme = TPM2_ALG_NULL;
        } else if (mode == 1) {
            scheme.scheme = TPM2_ALG_RSAES;
        } else if (mode == 2) {
            scheme.scheme = TPM2_ALG_OAEP;
            scheme.details.oaep.hashAlg = TPM2_ALG_SHA1;
        }
        r = Esys_RSA_Encrypt(esys_context, primaryHandle, ESYS_TR_NONE,
                             ESYS_TR_NONE, ESYS_TR_NONE, &plain, &scheme,
                             null_data, &cipher);
        goto_if_error(r, "Error esys rsa encrypt", error);

        Esys_Free(null_data);

        r = Esys_RSA_Decrypt(esys_context, primaryHandle,
                             ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE,
                             cipher, &scheme, null_data, &plain2);
        goto_if_error(r, "Error esys rsa decrypt", error);

        Esys_Free(null_data);
        Esys_Free(cipher);

        if (mode > 0 && memcmp(&plain.buffer[0], &plain2->buffer[0], plain_size)) {
            LOG_ERROR("plain texts are not equal for mode %i", mode);
            goto error;
        }

        r = Esys_FlushContext(esys_context, primaryHandle);
        goto_if_error(r, "Error: FlushContext", error);
        Esys_Free(plain2);
    }

    LOG_INFO("RSA-Encrypt-Decrypt Test Passed!");

    return EXIT_SUCCESS;

 error:

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(cipher);
    Esys_Free(plain2);
    Esys_Free(null_data);
    return EXIT_FAILURE;
}

//=== copied from tpm2-tss/test/integration/esys-ecdh-keygen.int.c ============
int
test_esys_ecdh_keygen(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR eccHandle = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE;
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,.keyBits = {.aes =
                                                                    128},.mode =
        {.aes = TPM2_ALG_CFB}
    };
    TPMA_SESSION sessionAttributes;
    TPM2B_NONCE nonceCaller = {
        .size = 20,
        .buffer = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
    };

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TPM2B_ECC_POINT *zPoint = NULL;
    TPM2B_ECC_POINT *pubPoint = NULL;

    memset(&sessionAttributes, 0, sizeof sessionAttributes);

    r = Esys_StartAuthSession(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                              ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                              &nonceCaller,
                              TPM2_SE_HMAC, &symmetric, TPM2_ALG_SHA1,
                              &session);
    goto_if_error(r, "Error: During initialization of session", error);

    TPM2B_SENSITIVE_CREATE inSensitive = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0}
                 ,
             },
            .data = {
                 .size = 0,
                 .buffer = {0}
             }
        }
    };
    TPM2B_PUBLIC inPublicECC = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_ECC,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_DECRYPT |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.eccDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                 },
                 .scheme = {
                      .scheme = TPM2_ALG_NULL,
                      .details = {}
                  },
                 .curveID = TPM2_ECC_NIST_P256,
                 .kdf = {.scheme = TPM2_ALG_NULL,
                         .details = {}
                  }
             },
            .unique.ecc = {
                 .x = {.size = 0,.buffer = {}},
                 .y = {.size = 0,.buffer = {}}
             }
            ,
        }
    };
    LOG_INFO("ECC key will be created.");
    TPM2B_PUBLIC inPublic = inPublicECC;

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {}
        ,
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, session,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitive, &inPublic,
                           &outsideInfo, &creationPCR, &eccHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esapi create primary", error);

    r = Esys_ECDH_KeyGen(
        esys_context,
        eccHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &zPoint,
        &pubPoint);
    goto_if_error(r, "Error: ECDH_KeyGen", error);

    r = Esys_FlushContext(esys_context, eccHandle);
    goto_if_error(r, "Error during FlushContext", error);

    r = Esys_FlushContext(esys_context, session);
    goto_if_error(r, "Flushing context", error);

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    Esys_Free(zPoint);
    Esys_Free(pubPoint);

    LOG_INFO("ECDH-Keygen Test Passed!");

    return EXIT_SUCCESS;

 error:
    LOG_ERROR("Error Code: %x\n", r);

    if (session != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, session) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup session failed.");
        }
    }

    if (eccHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, eccHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup eccHandle failed.");
        }
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    Esys_Free(zPoint);
    Esys_Free(pubPoint);
    return EXIT_FAILURE;
}

//=== copied from tpm2-tss/test/integration/esys-certify-creation.int.c =======
int
test_esys_certify(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR signHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;
    TPM2B_ATTEST *certifyInfo = NULL;
    TPMT_SIGNATURE *signature = NULL;

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = {
                 .size = 0,
                 .buffer = {0},
             },
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    inSensitivePrimary.sensitive.userAuth = authValuePrimary;

    TPM2B_PUBLIC inPublic = {
            .size = 0,
            .publicArea = {
                .type = TPM2_ALG_RSA,
                .nameAlg = TPM2_ALG_SHA1,
                .objectAttributes = (
                    TPMA_OBJECT_USERWITHAUTH |
                    TPMA_OBJECT_RESTRICTED |
                    TPMA_OBJECT_SIGN_ENCRYPT |
                    TPMA_OBJECT_FIXEDTPM |
                    TPMA_OBJECT_FIXEDPARENT |
                    TPMA_OBJECT_SENSITIVEDATAORIGIN
                    ),
                .authPolicy = {
                        .size = 0,
                    },
                .parameters.rsaDetail = {
                    .symmetric = {
                        .algorithm = TPM2_ALG_NULL,
                        .keyBits.aes = 128,
                        .mode.aes = TPM2_ALG_CFB,
                        },
                    .scheme = {
                         .scheme = TPM2_ALG_RSASSA,
                         .details = { .rsassa = { .hashAlg = TPM2_ALG_SHA1 }},

                    },
                    .keyBits = 2048,
                    .exponent = 0,
                },
                .unique.rsa = {
                        .size = 0,
                        .buffer = {},
                    },
            },
        };

    TPM2B_AUTH authValue = {
                .size = 0,
                .buffer = {}
    };


    TPM2B_DATA outsideInfo = {
            .size = 0,
            .buffer = {},
    };


    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    LOG_INFO("RSA key will be created.");

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE, &inSensitivePrimary,
                           &inPublic, &outsideInfo, &creationPCR,
                           &signHandle, &outPublic, &creationData,
                           &creationHash, &creationTicket);
    goto_if_error(r, "Error esys create primary", error);

    TPM2B_DATA qualifyingData = {0};
    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };

    r = Esys_Certify (
        esys_context,
        signHandle,
        signHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        &qualifyingData,
        &inScheme,
        &certifyInfo,
        &signature
        );
    goto_if_error(r, "Error: Certify", error);

    r = Esys_FlushContext(esys_context,signHandle);
    goto_if_error(r, "Error: FlushContext", error);

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(certifyInfo);
    Esys_Free(signature);

    LOG_INFO("RSA Certify Test Passed!");

    return EXIT_SUCCESS;

 error:

    if (signHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, signHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup signHandle failed.");
        }
    }
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);
    Esys_Free(certifyInfo);
    Esys_Free(signature);
    return EXIT_FAILURE;
}

//=== copied from tpm2-tss/test/integration/esys-verify-signature.int.c =======
int
test_esys_verify_signature(ESYS_CONTEXT * esys_context)
{
    TSS2_RC r;
    ESYS_TR primaryHandle = ESYS_TR_NONE;

    TPM2B_PUBLIC *outPublic = NULL;
    TPM2B_CREATION_DATA *creationData = NULL;
    TPM2B_DIGEST *creationHash = NULL;
    TPMT_TK_CREATION *creationTicket = NULL;

    TPM2B_NAME *nameKeySign = NULL;
    TPM2B_NAME *keyQualifiedName = NULL;
    TPMT_SIGNATURE *signature = NULL;

    TPMT_TK_VERIFIED *validation = NULL;

    /*
     * 1. Create Primary. This primary will be used as signing key.
     */

    TPM2B_AUTH authValuePrimary = {
        .size = 5,
        .buffer = {1, 2, 3, 4, 5}
    };

    TPM2B_SENSITIVE_CREATE inSensitivePrimary = {
        .size = 0,
        .sensitive = {
            .userAuth = authValuePrimary,
            .data = {
                 .size = 0,
                 .buffer = {0},
             },
        },
    };

    TPM2B_PUBLIC inPublic = {
        .size = 0,
        .publicArea = {
            .type = TPM2_ALG_RSA,
            .nameAlg = TPM2_ALG_SHA1,
            .objectAttributes = (TPMA_OBJECT_USERWITHAUTH |
                                 TPMA_OBJECT_SIGN_ENCRYPT  |
                                 TPMA_OBJECT_FIXEDTPM |
                                 TPMA_OBJECT_FIXEDPARENT |
                                 TPMA_OBJECT_SENSITIVEDATAORIGIN),
            .authPolicy = {
                 .size = 0,
             },
            .parameters.rsaDetail = {
                 .symmetric = {
                     .algorithm = TPM2_ALG_NULL,
                     .keyBits.aes = 128,
                     .mode.aes = TPM2_ALG_CFB},
                 .scheme = {
                      .scheme = TPM2_ALG_RSAPSS,
                      .details = {
                          .rsapss = { .hashAlg = TPM2_ALG_SHA1 }
                      }
                  },
                 .keyBits = 2048,
                 .exponent = 0,
             },
            .unique.rsa = {
                 .size = 0,
                 .buffer = {},
             },
        },
    };
    LOG_INFO("RSA key will be created.");

    TPM2B_DATA outsideInfo = {
        .size = 0,
        .buffer = {},
    };

    TPML_PCR_SELECTION creationPCR = {
        .count = 0,
    };

    TPM2B_AUTH authValue = {
        .size = 0,
        .buffer = {}
    };

    r = Esys_TR_SetAuth(esys_context, ESYS_TR_RH_OWNER, &authValue);
    goto_if_error(r, "Error: TR_SetAuth", error);

    r = Esys_CreatePrimary(esys_context, ESYS_TR_RH_OWNER, ESYS_TR_PASSWORD,
                           ESYS_TR_NONE, ESYS_TR_NONE,
                           &inSensitivePrimary, &inPublic,
                           &outsideInfo, &creationPCR, &primaryHandle,
                           &outPublic, &creationData, &creationHash,
                           &creationTicket);
    goto_if_error(r, "Error esys create primary", error);
    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    r = Esys_ReadPublic(esys_context,
                        primaryHandle,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        ESYS_TR_NONE,
                        &outPublic,
                        &nameKeySign,
                        &keyQualifiedName);
    goto_if_error(r, "Error: ReadPublic", error);


    TPMT_SIG_SCHEME inScheme = { .scheme = TPM2_ALG_NULL };
    TPMT_TK_HASHCHECK hash_validation = {
        .tag = TPM2_ST_HASHCHECK,
        .hierarchy = TPM2_RH_OWNER,
        .digest = {0}
    };
    /* SHA1 digest for PCR register with zeros */
    TPM2B_DIGEST pcr_digest_zero = {
        .size = 20,
        .buffer = { 0x67, 0x68, 0x03, 0x3e, 0x21, 0x64, 0x68, 0x24, 0x7b, 0xd0,
                    0x31, 0xa0, 0xa2, 0xd9, 0x87, 0x6d, 0x79, 0x81, 0x8f, 0x8f }
    };

    /*
     * 1. Sign pcr_digest_zero and verfiy the signature.
     */

    r = Esys_Sign(
        esys_context,
        primaryHandle,
        ESYS_TR_PASSWORD,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcr_digest_zero,
        &inScheme,
        &hash_validation,
        &signature);
    goto_if_error(r, "Error: Sign", error);

    r = Esys_VerifySignature(
        esys_context,
        primaryHandle,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        ESYS_TR_NONE,
        &pcr_digest_zero,
        signature,
        &validation);
    goto_if_error(r, "Error: Sign", error);

    r = Esys_FlushContext(esys_context, primaryHandle);
    goto_if_error(r, "Error: FlushContext", error);

    Esys_Free(outPublic);

    Esys_Free(nameKeySign);
    Esys_Free(keyQualifiedName);
    Esys_Free(signature);
    Esys_Free(validation);

    LOG_INFO("RSA Verify Test Passed!");

    return EXIT_SUCCESS;

 error:

    if (primaryHandle != ESYS_TR_NONE) {
        if (Esys_FlushContext(esys_context, primaryHandle) != TSS2_RC_SUCCESS) {
            LOG_ERROR("Cleanup primaryHandle failed.");
        }
    }

    Esys_Free(outPublic);
    Esys_Free(creationData);
    Esys_Free(creationHash);
    Esys_Free(creationTicket);

    Esys_Free(nameKeySign);
    Esys_Free(keyQualifiedName);
    Esys_Free(signature);
    Esys_Free(validation);
    return EXIT_FAILURE;
}

//=== execute tests ===========================================================
void main() {
  TSS2_RC ret = 0;
  size_t size = 0;
  TSS2_TCTI_CONTEXT *tcti_ctx = NULL;
  ESYS_CONTEXT *esys_ctx = NULL;

  TSS2_ABI_VERSION abi_version = {
    .tssCreator = 1,
    .tssFamily = 2,
    .tssLevel = 1,
    .tssVersion = 108,
  };

  // Zephyr_Init is called w/o a ptr, it returns the tcti_ctx size
  ret = Tss2_Tcti_Zephyr_Init(NULL, &size, NULL);
  if(ret != TPM2_RC_SUCCESS) {
    LOG_ERR("Faled to get allocation size for tcti");
    return;
  }

  tcti_ctx = calloc(1, size);
  if (tcti_ctx == NULL) {
    LOG_ERR("Faled to alloc space for tcti");
    return;
  }

  // Zephyr_Init takes a device name as argument
  ret = Tss2_Tcti_Zephyr_Init(tcti_ctx, &size, "tpm");
  if (ret != TSS2_RC_SUCCESS) {
    LOG_ERR("Failed to initialize tcti context");
    free(tcti_ctx);
    return;
  }

  // Esys_Initialize can also be called w/o tcti_ctx
  // in that case it will create an internal tcti_ctx
  // assuming the device name "tpm".
  ret = Esys_Initialize(&esys_ctx, tcti_ctx, &abi_version);
  if(ret != TPM2_RC_SUCCESS) {
    LOG_ERR("Failed to initialize esys context");
    free(tcti_ctx);
    return;
  }

  if(test_esys_get_random(esys_ctx) != EXIT_SUCCESS) {
    Esys_Finalize(&esys_ctx);
    free(tcti_ctx);
    return;
  }

  if(test_esys_rsa_encrypt_decrypt(esys_ctx) != EXIT_SUCCESS) {
    Esys_Finalize(&esys_ctx);
    free(tcti_ctx);
    return;
  }

  if(test_esys_ecdh_keygen(esys_ctx) != EXIT_SUCCESS) {
    Esys_Finalize(&esys_ctx);
    free(tcti_ctx);
    return;
  }

  if(test_esys_certify(esys_ctx) != EXIT_SUCCESS) {
    Esys_Finalize(&esys_ctx);
    free(tcti_ctx);
    return;
  }

  if(test_esys_verify_signature(esys_ctx) != EXIT_SUCCESS) {
    Esys_Finalize(&esys_ctx);
    free(tcti_ctx);
    return;
  }

  Esys_Finalize(&esys_ctx);
  free(tcti_ctx);

  return;
}

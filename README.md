# Proof of Concept: Zepher TPM2 Software Stack

## Overview
This repo tests the requirements (Code size and Memory size) for running
tpm2-tss on [Zephyr](https://www.zephyrproject.org). The PoC is implemented
on top of the Enhanced System API (ESAPI), since the Feature API (FAPI)
adds additional dependencies to JSON-C and OpenSSL. Moreover, the
[tpm2-tools](https://github.com/tpm2-software/tpm2-tools) are also implemented
on top of ESAPI, therefore the ESAPI should be sufficient. This PoC does not
yet implement an engine for mbedtls, it instead just runs a selection of ESYS
integration tests that should cover all API required when implementing an
engine for mbedtls:

- esys-get-random
- esys-rsa-encrypt-decrypt
- esys-ecdh-keygen
- esys-certify-creation
- esys-verify-signature

## Hardware Requirements
The PoC is tested with an [Infineon SLB 9670 TPM2.0 Arduino HAT](https://buyzero.de/products/arduino-adapter-for-letstrust-tpm)
on an [NXP FRDM-K64F](https://docs.zephyrproject.org/latest/boards/arm/frdm_k64f/doc/index.html)
but should work with any MCU - TPM 2.0 combination as long as the SPI-subsystem
does not release the chip-select between consecutive transfers.

## Software Requirements
- [Zephyr](https://github.com/zephyrproject-rtos)
- [TPM TIS](https://github.com/drandreas/tpm-tis-spi)
- [TPM2 TSS](https://github.com/tpm2-software/tpm2-tss)
- [TPM2 TSS Zephyr](https://github.com/drandreas/tpm2-tss-zephyr)

## Checkout using WEST
```
west init -m https://github.com/drandreas/zephyr-tpm2-poc.git zephyr-tpm2-poc
cd zephyr-tpm2-poc
west update
```
## Build and flash
```
west build -p -b frdm_k64f zephyr-tpm2-poc
west flash
```

## Aproximate memory and flash size
```
Memory region         Used Size  Region Size  %age Used
           FLASH:       92384 B         1 MB      8.81%
            SRAM:       11776 B       192 KB      5.99%
        IDT_LIST:         104 B         2 KB      5.08%
```
Note: The heap size, a couple of kB, is not included in this numbers.

## Expected output
```
*** Booting Zephyr OS build zephyr-v2.3.0-9-gd81be8fd9c3d  ***
[00:00:00.261,000] <inf> tpm_tis_spi: TPM 2.0 (device-id 0x1b, rev-id 16)
[00:00:00.415,000] <inf> tpm2: GetRandom Test Passed!
[00:00:02.021,000] <inf> tpm2: GetRandom with session Test Passed!
[00:00:02.021,000] <inf> tpm2: RSA key will be created.
[00:01:48.318,000] <inf> tpm2: RSA-Encrypt-Decrypt Test Passed!
[00:01:48.472,000] <inf> tpm2: ECC key will be created.
[00:01:49.348,000] <inf> tpm2: ECDH-Keygen Test Passed!
[00:01:49.348,000] <inf> tpm2: RSA key will be created.
[00:02:01.214,000] <inf> tpm2: RSA Certify Test Passed!
[00:02:01.214,000] <inf> tpm2: RSA key will be created.
[00:02:40.250,000] <inf> tpm2: RSA Verify Test Passed!
```

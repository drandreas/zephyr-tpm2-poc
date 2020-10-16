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
Values with bare minimum: (no log, fs, net, shell):
```
Memory region         Used Size  Region Size  %age Used
           FLASH:      112988 B         1 MB     10.78%
            SRAM:        4552 B       192 KB      2.32%
        IDT_LIST:         104 B         2 KB      5.08%
```

Values with filesystem and network stack:
```
Memory region         Used Size  Region Size  %age Used
           FLASH:      161748 B         1 MB     15.43%
            SRAM:       38816 B       192 KB     19.74%
        IDT_LIST:         152 B         2 KB      7.42%
```

Values with filesystem, network, logging and shell:
```
Memory region         Used Size  Region Size  %age Used
           FLASH:      232584 B         1 MB     22.18%
            SRAM:       58528 B       192 KB     29.77%
        IDT_LIST:         216 B         2 KB     10.55%
[531/531] Linking C executable zephyr/zephyr.elf
```
Note: The heap size, a couple of kB, is not included in this numbers.

## Expected output
```
*** Booting Zephyr OS build zephyr-v2.4.0  ***
[00:00:00.057,000] <inf> tpm_tis_spi: TPM 2.0 (device-id 0x1b, rev-id 22)
[00:00:00.057,000] <inf> littlefs: LittleFS version 2.2, disk version 2.0
[00:00:00.057,000] <inf> littlefs: FS at flash:0x80000 is 128 0x1000-byte blocks with 512 cycle
[00:00:00.057,000] <inf> littlefs: sizes: rd 16 ; pr 16 ; ca 64 ; la 32
[00:00:00.057,000] <inf> littlefs: /lfs mounted
[00:00:00.074,000] <inf> tpm2: GetRandom Test Passed!
[00:00:00.379,000] <inf> tpm2: GetRandom with session Test Passed!
[00:00:00.379,000] <inf> tpm2: RSA key will be created.
[00:00:03.001,000] <inf> eth_mcux: ETH_0 enabled 100M full-duplex mode.
[00:00:58.984,000] <inf> tpm2: RSA-Encrypt-Decrypt Test Passed!
[00:00:59.000,000] <inf> tpm2: ECC key will be created.
[00:00:59.517,000] <inf> tpm2: ECDH-Keygen Test Passed!
[00:00:59.517,000] <inf> tpm2: RSA key will be created.
[00:02:04.777,000] <inf> tpm2: RSA Certify Test Passed!
[00:02:04.777,000] <inf> tpm2: RSA key will be created.
[00:02:46.805,000] <inf> tpm2: RSA Verify Test Passed!
```

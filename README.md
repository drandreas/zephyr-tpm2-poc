# Proof of Concept: Zepher TPM2 Software Stack

## Overview
This repo will demonstrates the use of a TPM 2.0 for server authentication on
[Zephyr](https://www.zephyrproject.org). The PoC is implemented on top of the
Enhanced System API (ESAPI), since the Feature API (FAPI) adds additional
dependencies to JSON-C and OpenSSL. Moreover, the
[tpm2-tools](https://github.com/tpm2-software/tpm2-tools) are also implemented
on top of ESAPI, therefore the ESAPI is sufficient. The glue code is work in
progress but should be done in a couple of weeks.

## Hardware Requirements
The driver works with MCU that have SPI drivers that honor `SPI_HOLD_ON_CS` and
`SPI_LOCK_ON` only. If the hardware IP block does not support `SPI_HOLD_ON_CS`
it is recommendet to use gpio-cs control.

The PoC is tested using an [Infineon SLB 9670 TPM2.0 Arduino HAT](https://buyzero.de/products/arduino-adapter-for-letstrust-tpm)
on:
 - [NXP FRDM-K64F](https://docs.zephyrproject.org/latest/boards/arm/frdm_k64f/doc/index.html)
 - [nRF52 DK](https://docs.zephyrproject.org/latest/boards/arm/nrf52dk_nrf52832/doc/index.html)

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
```sh
~ $ west build -p -b frdm_k64f zephyr-tpm2-poc
# or
~ $ west build -p -b frdm_k64f zephyr-tpm2-poc -- -DCONF_FILE=prj.min.conf
# or
~ $ west build -p -b nrf52dk_nrf52832 zephyr-tpm2-poc/
# followed by
~ $ west flash
```

## Aproximate memory and flash size
Stripped down image (prj.min.conf):
```
Memory region         Used Size  Region Size  %age Used
           FLASH:      185408 B         1 MB     17.68%
            SRAM:       57088 B       192 KB     29.04%
        IDT_LIST:         152 B         2 KB      7.42%
```

Full image (default prj.conf)
```
Memory region         Used Size  Region Size  %age Used
           FLASH:      298164 B         1 MB     28.44%
            SRAM:       81408 B       192 KB     41.41%
        IDT_LIST:         216 B         2 KB     10.55%
```
Note: The heap size, a couple of kB, is not included in this numbers.

## Test Server
Target Output:
```
*** Booting Zephyr OS build zephyr-v2.4.0  ***
[00:00:00.060,000] <inf> tpm_tis_spi: TPM 2.0 (device-id 0x1b, rev-id 22)
[00:00:00.060,000] <inf> littlefs: LittleFS version 2.2, disk version 2.0
[00:00:00.060,000] <inf> littlefs: FS at FLASH_CTRL:0x80000 is 128 0x1000-byte blocks with 512 cycle
[00:00:00.060,000] <inf> littlefs: sizes: rd 16 ; pr 16 ; ca 64 ; la 32
[00:00:00.060,000] <inf> littlefs: /lfs mounted
[00:00:00.077,000] <inf> tpm2: GetRandom Test Passed!
[00:00:03.001,000] <inf> eth_mcux: ETH_0 enabled 100M full-duplex mode.
[00:00:05.077,000] <inf> tpm2: My IPv6 Address: fe80::1234:5678]
[00:00:05.078,000] <inf> tpm2: Waiting for TCP connection on port 4433
```

Connect from a Linux/Mac/Windows using openssl (you need to adjust the scope ID to match your outgoing interface):
```
openssl s_client -showcerts -CAfile zephyr-tpm2-poc/data/ca.pem -servername zephyr -connect "[fe80::1234:5678%eth0]"
```

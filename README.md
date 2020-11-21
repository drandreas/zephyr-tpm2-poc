# Proof of Concept: Zepher TPM2 Software Stack

## Overview
This repo demonstrates the use of a TPM 2.0 for server authentication on
[Zephyr](https://www.zephyrproject.org). The PoC is implemented on top of the
Enhanced System API (ESAPI), since the Feature API (FAPI) adds additional
dependencies to JSON-C and OpenSSL. Moreover, the
[tpm2-tools](https://github.com/tpm2-software/tpm2-tools) are also implemented
on top of ESAPI, therefore the ESAPI is sufficient.

The main has 2 code path. This first will generate an CSR on every boot.
The second will launch an TLS 1.2 echo server on port 4433 (IPv6).

## Hardware Requirements
The driver works with MCUs that have SPI drivers that honor `SPI_HOLD_ON_CS` and
`SPI_LOCK_ON` only. If the hardware IP block does not support `SPI_HOLD_ON_CS`
it is recommendet to use gpio-cs control.

The PoC is tested using an [Infineon SLB 9670 TPM2.0 Arduino HAT](https://buyzero.de/products/arduino-adapter-for-letstrust-tpm)
on:
 - [NXP FRDM-K64F](https://docs.zephyrproject.org/latest/boards/arm/frdm_k64f/doc/index.html)
 - [nRF52 DK](https://docs.zephyrproject.org/latest/boards/arm/nrf52dk_nrf52832/doc/index.html) (has no ethernet interface)

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
           FLASH:      197000 B         1 MB     18.79%
            SRAM:         60 KB       192 KB     31.25%
        IDT_LIST:         152 B         2 KB      7.42%
```

Full image (default prj.conf)
```
Memory region         Used Size  Region Size  %age Used
           FLASH:      293132 B         1 MB     27.96%
            SRAM:       74160 B       192 KB     37.72%
        IDT_LIST:         216 B         2 KB     10.55%
```
Note: The heap size, a couple of kB, is not included in this numbers.

## Test Server
Target output during inital boot:
```
*** Booting Zephyr OS build zephyr-v2.4.0  ***
Server CRT or TPM Blob not compiled in, Creating CSR
Please change the source code and assign the PEM below to "tpm_blob[]"
-----BEGIN TSS2 PRIVATE KEY-----
MIHNBgdngQUKAQMAoAMBAf8CAQEEWABWACMACwAEBHIAAAAQABAAAwAQACA+QUDa
4kSqSBZCOsYowd+lHNqZWxb3waDtd3wICwigcQAgO4u8jri79avPyOXm9fwUnuEo
/ei+UKQ4vXCMDjowCdAEYABeACCA6d13/ZdvCtVOAfqyD73gmYYCuyZI/zJLIRTw
uAWE4QAQMPQPyl7V5MFH7MbTZkV6YrhcQyK473XR6MALh4NcjAQYvV6AQPyXLyon
eQhtw1dV19WP5zxdSax2IQ==
-----END TSS2 PRIVATE KEY-----

Please sign the PEM on your desktop and assign the certificate to "server_certificate[]"
Hint: cd zephyr-tpm2-poc/data
      openssl ca -config openssl.cnf -startdate 200101000000Z -enddate 300101000000Z -in /dev/stdin

-----BEGIN CERTIFICATE REQUEST-----
MIHsMIGRAgEAMBExDzANBgNVBAMMBnplcGh5cjBZMBMGByqGSM49AgEGCCqGSM49
AwEHA0IABD5BQNriRKpIFkI6xijB36Uc2plbFvfBoO13fAgLCKBxO4u8jri79avP
yOXm9fwUnuEo/ei+UKQ4vXCMDjowCdCgHjAcBgkqhkiG9w0BCQ4xDzANMAsGA1Ud
DwQEAwIDyDAMBggqhkjOPQQDAgUAA0gAMEUCIBoxjDl7MsLxkwXzLUV2tmUdxpu8
4owovJfUCCgdwoz9AiEA7oc3AFcvblYO6VSpGNagvymnVqH2gAIAh5yBQDmhzr4=
-----END CERTIFICATE REQUEST-----
```

Target output after CRT and TPM Blob have been assigned (in source code):
```
*** Booting Zephyr OS build zephyr-v2.4.0  ***
[00:00:00.060,000] <inf> tpm_tis_spi: TPM 2.0 (device-id 0x1b, rev-id 22)
[00:00:00.060,000] <inf> tpm2: Preparing TPM Blob for echo_server...
[00:00:03.001,000] <inf> eth_mcux: ETH_0 enabled 100M full-duplex mode.
[00:00:05.061,000] <inf> tpm2: My IPv6 Address: [fe80::1234:5678]
[00:00:05.061,000] <inf> tpm2: Waiting for TCP connection on port 4433
```

Connect from a Linux/Mac/Windows using openssl (you need to adjust the scope ID to match your outgoing interface):
```
openssl s_client -showcerts -CAfile zephyr-tpm2-poc/data/ca.pem -servername zephyr -connect "[fe80::1234:5678%eth0]"
```

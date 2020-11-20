#include <logging/log.h>
#include <random/rand32.h>

#if CONFIG_BOARD_FRDM_K64F
#include <fsl_port.h>
#include <drivers/pinmux.h>
#endif

#include <net/socket.h>
#include <net/tls_credentials.h>

#include <mbedtls/pem.h>
#include <mbedtls/x509_csr.h>
#include <mbedtls/tpm-utils.h>

#include <stdio.h>

// Loglevel of main function
LOG_MODULE_REGISTER(tpm2, LOG_LEVEL_DBG);

// Certificate and Key
#define SERVER_CERTIFICATE_TAG 1

static const char ca_certificate[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIBqTCCAS+gAwIBAgIBADAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApUUE0tUG9D\r\n"
  "IENBMB4XDTIwMDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAwMFowFTETMBEGA1UEAwwK\r\n"
  "VFBNLVBvQyBDQTB2MBAGByqGSM49AgEGBSuBBAAiA2IABD7i3xfIQVr9WEugrfXf\r\n"
  "DTJNzqwOLqZoPaEXiFGo9J1JDkHrMftJAv2KWhebATNYS9EzN8hffc0/fz+cv8qr\r\n"
  "pfFqu9J+eoGkax0lQS1dRR+I40X6QZ0c4+cuk6CGowiyVqNTMFEwHQYDVR0OBBYE\r\n"
  "FDFm5sVrTGo3eZQ9OjlU6qPZ1bIKMB8GA1UdIwQYMBaAFDFm5sVrTGo3eZQ9OjlU\r\n"
  "6qPZ1bIKMA8GA1UdEwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDaAAwZQIxAN5/2ZCM\r\n"
  "R7vurAPiQGkfE5o69yYClmHZbQHJyZF5afSf5OJhce04kCrUKtyQOcgYfQIwWqud\r\n"
  "9h7syP1e17rXfIK7nfrRdu4IZjdGyIcgu3rM2C4bBuoDcqxZbbSlHiZDmoX6\r\n"
  "-----END CERTIFICATE-----\r\n";

static const char server_certificate[] = "";

// This Private key is needed to make Zephyr's secure socket code happy
// The key can be arbitrary as long as it belongs to the P-256 curve.
static const char private_key[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguFQIs7wj7F0TOF9p\r\n"
  "IjAO13TNoVz6uhgq7F0WBex6+yihRANCAASPpRIl7cNR85WpA1AELRhT7EhD3EU2\r\n"
  "9b8k9q2dwRbN6lXaf8YXvm0rTYWtHM25iaSA+oUtb6KwIzzDJiXMndKx\r\n"
  "-----END PRIVATE KEY-----\r\n";

static const char tpm_blob[] = "";

static tpm_keypair_t keypair;

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

#if CONFIG_CONSOLE
static int get_random(void* context, unsigned char *buffer, size_t buf_size) {
  (void)context;

  if(sys_csrand_get(buffer, buf_size) != 0) {
    return -EIO;
  }

  return buf_size;
}
#endif

#if CONFIG_BOARD_FRDM_K64F
// Change K64's CS-Pin to GPIO (SPI HW-CS releases pin to early)
static int pinmux_reconfigure(const struct device *dev) {
  pinmux_pin_set(device_get_binding(CONFIG_PINMUX_MCUX_PORTD_NAME),
                 DT_SPI_DEV_CS_GPIOS_PIN(DT_NODELABEL(spi_tpm)),
                 PORT_PCR_MUX(kPORT_MuxAsGpio));
  return 0;
}
SYS_INIT(pinmux_reconfigure, POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE);
#endif

// Main Application
void main() {
  int ret = 0;

  if(strlen(server_certificate) == 0 || strlen(tpm_blob) == 0) {
#if CONFIG_CONSOLE
    puts("Server CRT or TPM Blob not compiled in, Creating CSR");

    ret = tpm_generate_ec_keypair(&keypair);
    if(ret != 0) {
      LOG_ERR("Failed to generate ec keypair");
      return;
    }

    // Output TPM Blob
    char der_buf[512];
    size_t der_len = sizeof(der_buf);
    ret = tpm_store_keypair_der(&keypair, der_buf, &der_len);
    if(ret < 0) {
      LOG_ERR("Failed to store ec keypair");
      return;
    }

    char pem_buf[512];
    memset(pem_buf, 0, sizeof(pem_buf));
    size_t pem_len = 0;
    char* p = &der_buf[0];
    ret = mbedtls_pem_write_buffer("-----BEGIN TSS2 PRIVATE KEY-----\n",
                                   "-----END TSS2 PRIVATE KEY-----\n",
                                   p, der_len,
                                   pem_buf, sizeof(pem_buf), &pem_len);
    if(ret != 0)
    {
      LOG_ERR("Failed to generate tpm data");
      return;
    }
    puts("Please change the source code and assign the PEM below to \"tpm_blob[]\"");
    puts(pem_buf);

    // Create and output CSR
    tpm_set_ec_keypair(&keypair);
    mbedtls_pk_context pk_ctx;
    mbedtls_pk_init(&pk_ctx);

    ret = tpm_export_pubkey(&keypair.pub_key, &pk_ctx);
    if(ret != 0) {
      LOG_ERR("Failed to export pubkey");
      return;
    }

    static mbedtls_x509write_csr csr_ctx;
    mbedtls_x509write_csr_init(&csr_ctx);
    mbedtls_x509write_csr_set_key(&csr_ctx, &pk_ctx);
    mbedtls_x509write_csr_set_md_alg(&csr_ctx, MBEDTLS_MD_SHA256);

    ret = mbedtls_x509write_csr_set_subject_name(&csr_ctx, "CN=zephyr");
    if(ret != 0) {
      LOG_ERR("Failed to set subject name");
      return;
    }

    ret = mbedtls_x509write_csr_set_key_usage(&csr_ctx, MBEDTLS_X509_KU_DIGITAL_SIGNATURE
                                                      | MBEDTLS_X509_KU_NON_REPUDIATION
                                                      | MBEDTLS_X509_KU_KEY_AGREEMENT);
    if(ret != 0) {
      LOG_ERR("Failed to set key usage");
      return;
    }

    // Output CSR
    if(mbedtls_x509write_csr_pem(&csr_ctx,
                                 &pem_buf[0],
                                 sizeof(pem_buf),
                                 get_random,
                                 NULL) != 0)
    {
      LOG_ERR("Failed to generate csr");
      return;
    }

    puts("Please sign the PEM on your desktop and assign the certificate to \"server_certificate[]\"");
    puts("Hint: cd zephyr-tpm2-poc/data");
    puts("      openssl ca -config openssl.cnf -startdate 200101000000Z -enddate 300101000000Z -in /dev/stdin");
    puts(pem_buf);
    mbedtls_x509write_csr_free(&csr_ctx);
    mbedtls_pk_free(&pk_ctx);
#endif

    return;
  }

  // Load previously created TPM Blob
  // Note: The Blob  is compiled in - for the sake of simplicity, however the Blob is not interchangeable between TPMs
  LOG_INF("Preparing TPM Blob for echo_server...");
  struct mbedtls_pem_context pem;
  mbedtls_pem_init(&pem);
  size_t file_index = 0;
  ret = mbedtls_pem_read_buffer(&pem,
                                "-----BEGIN TSS2 PRIVATE KEY-----",
                                "-----END TSS2 PRIVATE KEY-----",
                                (const unsigned char*)tpm_blob,
                                NULL, 0,
                                &file_index);
  if(ret != 0) {
    LOG_ERR("Failed to read TPM blob");
    return;
  }

  ret = tpm_load_keypair_der(&keypair, pem.buf, pem.buflen);
  if(ret != 0) {
    LOG_ERR("Failed to parse TPM blob");
    return;
  }
  mbedtls_pem_free(&pem);
  tpm_set_ec_keypair(&keypair);

  // "Wait" for Ethernet Link
  k_sleep(K_SECONDS(5));

  // Output IPv6 Address
  struct net_if* netif = net_if_lookup_by_dev(device_get_binding("ETH_0"));
  struct net_if_ipv6 *ipv6 = netif->config.ip.ipv6;
  for (size_t i = 0; ipv6 && i < NET_IF_MAX_IPV6_ADDR; i++) {
    struct net_if_addr *addr = &ipv6->unicast[i];
    if(addr->is_used) {
      static char buf[NET_IPV6_ADDR_LEN];
      net_addr_ntop(AF_INET6, &addr->address.in6_addr, buf, NET_IPV6_ADDR_LEN);
      LOG_INF("My IPv6 Address: [%s]", log_strdup(buf));
    }
  }

  // Load Certificates and Private Key
  ret = tls_credential_add(SERVER_CERTIFICATE_TAG,
                           TLS_CREDENTIAL_CA_CERTIFICATE,
                           ca_certificate,
                           sizeof(ca_certificate));
  if(ret < 0) {
    LOG_ERR("Failed to register ca certificate");
    return;
  }

  ret = tls_credential_add(SERVER_CERTIFICATE_TAG,
                           TLS_CREDENTIAL_SERVER_CERTIFICATE,
                           server_certificate,
                           sizeof(server_certificate));
  if(ret < 0) {
    LOG_ERR("Failed to register server certificate");
    return;
  }

  ret = tls_credential_add(SERVER_CERTIFICATE_TAG,
                           TLS_CREDENTIAL_PRIVATE_KEY,
                           private_key, sizeof(private_key));
  if(ret < 0) {
    LOG_ERR("Failed to register private key");
    return;
  }

  // Create Secure Socket
  int sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TLS_1_2);
  if(sock < 0) {
    LOG_ERR("Failed to create TCP socket");
    return;
  }

  sec_tag_t sec_tag_list[] = {
    SERVER_CERTIFICATE_TAG,
  };

  ret = setsockopt(sock,
                   SOL_TLS,
                   TLS_SEC_TAG_LIST,
                   sec_tag_list,
                   sizeof(sec_tag_list));
  if (ret < 0) {
    LOG_ERR("Failed to set TCP secure option");
    return;
  }

  struct sockaddr_in6 addr6;
  (void)memset(&addr6, 0, sizeof(addr6));
  addr6.sin6_family = AF_INET6;
  addr6.sin6_port = htons(4433);
  ret = bind(sock, (struct sockaddr *)&addr6, sizeof(addr6));
  if (ret < 0) {
    LOG_ERR("Failed to bind TCP socket");
    return;
  }

  ret = listen(sock, 4);
  if (ret < 0) {
    LOG_ERR("Failed to listen on TCP socket");
    return;
  }

  // Serve Socket
  while(true) {
    LOG_INF("Waiting for TCP connection on port 4433");
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client = accept(sock, (struct sockaddr *)&client_addr, &client_addr_len);
    if (client < 0) {
      LOG_ERR("Failed to accept client");
      continue;
    }

    // Serve Client
    while(true) {
      char buf[80];
      int len = recv(client, buf, sizeof(buf), 0);
      if (len == 0) {
        LOG_INF("Received connection close");
        close(client);
        break;
      } else
      if (len < 0) {
        LOG_ERR("Faild to receive data");
        break;
      } else {
        LOG_INF("Received %i bytes", len);
        send(client, buf, len, 0);
      }
    }
  }

  // Cleanup
  close(sock);
  tls_credential_delete(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_CA_CERTIFICATE);
  tls_credential_delete(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_SERVER_CERTIFICATE);
  tls_credential_delete(SERVER_CERTIFICATE_TAG, TLS_CREDENTIAL_PRIVATE_KEY);

  return;
}

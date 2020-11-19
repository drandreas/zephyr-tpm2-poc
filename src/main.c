#include <logging/log.h>
#include <random/rand32.h>

#if CONFIG_BOARD_FRDM_K64F
#include <fsl_port.h>
#include <drivers/pinmux.h>
#endif

#include <net/socket.h>
#include <net/tls_credentials.h>

#include <tss2/tss2_tctildr.h>
#include <tss2/tss2_tcti_zephyr.h>
#include <tss2/tss2_esys.h>

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

static const char server_certificate[] =
  "-----BEGIN CERTIFICATE-----\r\n"
  "MIIBljCCARugAwIBAgIBATAKBggqhkjOPQQDAjAVMRMwEQYDVQQDDApUUE0tUG9D\r\n"
  "IENBMB4XDTIwMDEwMTAwMDAwMFoXDTMwMDEwMTAwMDAwMFowETEPMA0GA1UEAwwG\r\n"
  "emVwaHlyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEj6USJe3DUfOVqQNQBC0Y\r\n"
  "U+xIQ9xFNvW/JPatncEWzepV2n/GF75tK02FrRzNuYmkgPqFLW+isCM8wyYlzJ3S\r\n"
  "saNgMF4wCQYDVR0TBAIwADARBglghkgBhvhCAQEEBAMCBkAwHQYDVR0OBBYEFGnQ\r\n"
  "aSjGgHIa22h/YgNjDinQqOmRMB8GA1UdIwQYMBaAFDFm5sVrTGo3eZQ9OjlU6qPZ\r\n"
  "1bIKMAoGCCqGSM49BAMCA2kAMGYCMQCHKE/+rrr1LEsl9cBu53OHrkAyeDb2CGLx\r\n"
  "NDuWFZaxNRH+5ANZYHvnnv6lPCoEX4cCMQC6tEEPuZO0d08VDeruPJSZxKDwt1pu\r\n"
  "e5oRxdrnLu3Dhql0udsgGY9RY4kU2yLwfJg=\r\n"
  "-----END CERTIFICATE-----\r\n";

static const char private_key[] =
  "-----BEGIN PRIVATE KEY-----\r\n"
  "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQguFQIs7wj7F0TOF9p\r\n"
  "IjAO13TNoVz6uhgq7F0WBex6+yihRANCAASPpRIl7cNR85WpA1AELRhT7EhD3EU2\r\n"
  "9b8k9q2dwRbN6lXaf8YXvm0rTYWtHM25iaSA+oUtb6KwIzzDJiXMndKx\r\n"
  "-----END PRIVATE KEY-----\r\n";

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

// Test basic TPM Functionality / Connectivity
static int test_esys_get_random(ESYS_CONTEXT * esys_context) {
  TSS2_RC ret;

  TPM2B_DIGEST *randomBytes;
  ret = Esys_GetRandom(esys_context, ESYS_TR_NONE, 
                       ESYS_TR_NONE, ESYS_TR_NONE,
                       48, &randomBytes);
  if (ret != TPM2_RC_SUCCESS) {
    LOG_ERR("GetRandom FAILED! Response Code : 0x%x", ret);
    return EXIT_FAILURE;
  } else {
    Esys_Free(randomBytes);
    LOG_INF("GetRandom Test Passed!");
    return 0;
  }
}

// Main Application
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
  if(ret != TSS2_RC_SUCCESS) {
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
  Esys_Finalize(&esys_ctx);
  free(tcti_ctx);

  return;
}

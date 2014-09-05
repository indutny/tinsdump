#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <tins/tins.h>

using namespace Tins;

static void run(const char* iface, const char* key, const char* ssid);


static void usage(int argc, char** argv) {
  fprintf(stderr,
          "Usage:\n"
          "  %s --help\n"
          "  %s --key WPA-key --ssid SSID --iface interface\n",
          argv[0],
          argv[0]);
}


int main(int argc, char** argv) {
  static struct option opts[] = {
    { "iface", required_argument, NULL, 'i' },
    { "key", required_argument, NULL, 'k' },
    { "ssid", required_argument, NULL, 's' },
    { "help", no_argument, NULL, 'h' },
    { NULL, 0, NULL, 0 }
  };

  char ch;
  const char* iface = NULL;
  const char* key = NULL;
  const char* ssid = NULL;
  while ((ch = getopt_long(argc, argv, "i:k:s:h", opts, NULL)) != -1) {
    switch (ch) {
      case 'i':
        iface = optarg;
        break;
      case 'k':
        key = optarg;
        break;
      case 's':
        ssid = optarg;
        break;
      case 'h':
      default:
        usage(argc, argv);
        return 0;
    }
  }

  if (iface == NULL || key == NULL || ssid == NULL) {
    usage(argc, argv);
    return -1;
  }

  run(iface, key, ssid);

  return 0;
}


bool handler(PDU &pdu) {
  IP &ip = pdu.rfind_pdu<IP>();
  fprintf(stdout,
          "IP packet from %s to %s:\n",
          ip.src_addr().to_string().c_str(),
          ip.dst_addr().to_string().c_str());

  std::vector<uint8_t> vec = static_cast<PDU&>(ip).serialize();
  int i;
  for (i = 0; i < vec.size(); i++) {
    if (i % 16 == 0)
      fprintf(stdout, "0x%04x:", i);

    uint8_t byte = vec.at(i);
    fprintf(stdout, " %02x", byte);

    if (i % 16 == 15)
      fprintf(stdout, "\n");
  }
  if (i % 16 != 15)
    fprintf(stdout, "\n");

  return true;
}


void run(const char* iface, const char* key, const char* ssid) {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  config.set_rfmon(true);

  auto decrypt_proxy = Crypto::make_wpa2_decrypter_proxy(&handler);
  decrypt_proxy.decrypter().add_ap_data(key, ssid);

  Sniffer sniffer(iface, config);
  sniffer.sniff_loop(decrypt_proxy);
}

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tins/tins.h>

using namespace Tins;

struct tinsdump_args_t {
  const char* iface;
  const char* key;
  const char* ssid;
};

static void run(tinsdump_args_t* args);


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
  tinsdump_args_t args;

  char ch;
  memset(&args, 0, sizeof(args));
  while ((ch = getopt_long(argc, argv, "i:k:s:h", opts, NULL)) != -1) {
    switch (ch) {
      case 'i':
        args.iface = optarg;
        break;
      case 'k':
        args.key = optarg;
        break;
      case 's':
        args.ssid = optarg;
        break;
      case 'h':
      default:
        usage(argc, argv);
        return 0;
    }
  }

  if (args.iface == NULL || args.key == NULL || args.ssid == NULL) {
    usage(argc, argv);
    return -1;
  }

  run(&args);

  return 0;
}


static bool pdu_handler(PDU &pdu) {
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
    if (i % 2 == 0)
      fprintf(stdout, " %02x", byte);
    else
      fprintf(stdout, "%02x", byte);

    if (i % 16 == 15)
      fprintf(stdout, "\n");
  }
  if (i % 16 != 0)
    fprintf(stdout, "\n");
  fflush(stdout);

  return true;
}


void run(tinsdump_args_t* args) {
  SnifferConfiguration config;
  config.set_promisc_mode(true);
  config.set_rfmon(true);

  Crypto::DecrypterProxy<bool (*)(PDU&), Crypto::WPA2Decrypter> decrypt_proxy =
      Crypto::make_wpa2_decrypter_proxy(&pdu_handler);
  decrypt_proxy.decrypter().add_ap_data(args->key, args->ssid);

  Sniffer sniffer(args->iface, config);
  sniffer.sniff_loop(decrypt_proxy);
}

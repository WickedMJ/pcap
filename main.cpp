#include <pcap.h>
#include <stdio.h>
#include <libnet.h>


void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

void hdr(u_char* packet){
    printf("dst mac : %02X : %02X : %02X : %02X : %02X : %02X \n",
           packet[0],packet[1],packet[2],packet[3],packet[4],packet[5]);

    printf("src mac : %02X : %02X : %02X : %02X : %02X : %02X \n",
           packet[6],packet[7],packet[8],packet[9],packet[10],packet[11]);

    if(packet[12]==8 && packet[13]==0){     //IP check
        printf("src ip %d.%d.%d.%d\n",packet[26],packet[27],packet[28],packet[29]);
        printf("dst ip %d.%d.%d.%d\n",packet[30],packet[31],packet[32],packet[33]);

        if(packet[23]==6){     // Protocol check
            printf("TCP -> src port : %d\n",packet[34]*256 + packet[35]);
            printf("TCP -> dst port : %d\n",packet[36]*256 + packet[37]);

            if(packet[54]!=0){
                printf("DATA : ");
                for (int var = 54; var < 70; ++var) { //payload
                    printf("%02X ",packet[var]);
                }
            }
            printf("\n");
        }
    }
    printf("------------------------------------------------------\n");
}


int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    //ethhdr = (struct libnet_ethernet_hdr*) handle;

    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    hdr((u_char*)&packet[0]);
    //printf("%u bytes captured\n", header->caplen);
  }

  pcap_close(handle);
  return 0;
}

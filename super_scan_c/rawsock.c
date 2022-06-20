/*
    portable interface to "raw sockets"

    This uses both "libpcap" on systems, but on Linux, we try to use the
    basic raw sockets, bypassing libpcap for better performance.
*/
#include "rawsock.h"
#include "templ-pkt.h"
#include "logger.h"

#include "string_s.h"
#include "stub-pcap.h"
#include "stub-pfring.h"

#include "util-malloc.h"
#include <ctype.h>

static int is_pcap_file = 0;

#ifdef WIN32
#include <winsock.h>
#include <iphlpapi.h>

#if defined(_MSC_VER)
#pragma comment(lib, "IPHLPAPI.lib")
#endif

#elif defined(__GNUC__)

#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#else
#endif

#include "rawsock-adapter.h"

#define SENDQ_SIZE 65536 * 8


struct AdapterNames {
    char *easy_name;
    char *hard_name;
};

struct AdapterNames adapter_names[64];
unsigned adapter_name_count = 0;

/***************************************************************************
 ***************************************************************************/
#ifdef WIN32
int pcap_setdirection(pcap_t *pcap, pcap_direction_t direction)
{
    static int (*real_setdirection)(pcap_t *, pcap_direction_t) = 0;

    if (real_setdirection == 0) {
        void* h = LoadLibraryA("wpcap.dll");
        if (h == NULL) {
            fprintf(stderr, "couldn't load wpcap.dll: %u\n", 
                                (unsigned)GetLastError());
            return -1;
        }

        real_setdirection = (int (*)(pcap_t*,pcap_direction_t))
                            GetProcAddress(h, "pcap_setdirection");
        if (real_setdirection == 0) {
            fprintf(stderr, "couldn't find pcap_setdirection(): %u\n", 
                                (unsigned)GetLastError());
            return -1;
        }
    }

    return real_setdirection(pcap, direction);
}
#endif

/***************************************************************************
 ***************************************************************************/
void
rawsock_init(void) {
#ifdef WIN32
    /* Declare and initialize variables */

// It is possible for an adapter to have multiple
// IPv4 addresses, gateways, and secondary WINS servers
// assigned to the adapter.
//
// Note that this sample code only prints out the
// first entry for the IP address/mask, and gateway, and
// the primary and secondary WINS server for each adapter.

    PIP_ADAPTER_INFO pAdapterInfo;
    PIP_ADAPTER_INFO pAdapter = NULL;
    DWORD dwRetVal = 0;
    UINT i;

/* variables used to print DHCP time info */
    //struct tm newtime;
    //char buffer[32];
    //errno_t error;

    ULONG ulOutBufLen = sizeof (IP_ADAPTER_INFO);
    pAdapterInfo = (IP_ADAPTER_INFO *) malloc(sizeof (IP_ADAPTER_INFO));
    if (pAdapterInfo == NULL) {
        printf("Error allocating memory needed to call GetAdaptersinfo\n");
        return;
    }
// Make an initial call to GetAdaptersInfo to get
// the necessary size into the ulOutBufLen variable
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO *) malloc(ulOutBufLen);
        if (pAdapterInfo == NULL) {
            printf("Error allocating memory needed to call GetAdaptersinfo\n");
            return;
        }
    }

    if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
        for (pAdapter = pAdapterInfo; pAdapter; pAdapter = pAdapter->Next) {
            if (pAdapter->Type != MIB_IF_TYPE_ETHERNET)
                continue;

            //printf("\tComboIndex: \t%d\n", pAdapter->ComboIndex);
            //printf("\tAdapter Name: \t%s\n", pAdapter->AdapterName);
            {
                size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
                char *name = (char*)malloc(name_len);
                size_t addr_len = pAdapter->AddressLength * 3 + 1;
                char *addr = (char*)malloc(addr_len);

                if (name == NULL || addr == NULL)
                    exit(1);

                sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);

                //printf("\tAdapter Desc: \t%s\n", pAdapter->Description);
                //printf("\tAdapter Addr: \t");
                for (i = 0; i < pAdapter->AddressLength; i++) {
                    if (i == (pAdapter->AddressLength - 1))
                        sprintf_s(addr+i*3, addr_len-i*3, "%.2X", pAdapter->Address[i]);
                    else
                        sprintf_s(addr+i*3, addr_len-i*3, "%.2X-", pAdapter->Address[i]);
                }
                //printf("%s  ->  %s\n", addr, name);
                adapter_names[adapter_name_count].easy_name = addr;
                adapter_names[adapter_name_count].hard_name = name;
                adapter_name_count++;
            }

            //printf("\tIndex: \t%d\n", pAdapter->Index);

            {
                size_t name_len = strlen(pAdapter->AdapterName) + 12 + 1;
                char *name = (char*)malloc(name_len);
                size_t addr_len = strlen(pAdapter->IpAddressList.IpAddress.String) + 1;
                char *addr = (char*)malloc(addr_len);
                if (name == NULL || addr == NULL)
                    exit(1);
                sprintf_s(name, name_len, "\\Device\\NPF_%s", pAdapter->AdapterName);
                sprintf_s(addr, addr_len, "%s", pAdapter->IpAddressList.IpAddress.String);
                //printf("%s  ->  %s\n", addr, name);
                adapter_names[adapter_name_count].easy_name = addr;
                adapter_names[adapter_name_count].hard_name = name;
                adapter_name_count++;
            }

        }
    } else {
        printf("GetAdaptersInfo failed with error: %u\n", 
                                                    (unsigned)dwRetVal);

    }
    if (pAdapterInfo)
        free(pAdapterInfo);
#else
    PFRING_init();
#endif
    return;
}

/***************************************************************************
  * This function prints to the command line a list of all the network
  * interfaces/devices.
 ***************************************************************************/
void
rawsock_list_adapters(void) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (PCAP.findalldevs(&alldevs, errbuf) != -1) {
        int i;
        const pcap_if_t *d;
        i = 0;

        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for (d = alldevs; d; d = PCAP.dev_next(d)) {
            fprintf(stderr, " %d  %s \t", i++, PCAP.dev_name(d));
            if (PCAP.dev_description(d))
                fprintf(stderr, "(%s)\n", PCAP.dev_description(d));
            else
                fprintf(stderr, "(No description available)\n");
        }
        fprintf(stderr, "\n");
        PCAP.freealldevs(alldevs);
    } else {
        fprintf(stderr, "%s\n", errbuf);
    }
}

/***************************************************************************
 ***************************************************************************/
static const char *
adapter_from_index(unsigned index) {
    pcap_if_t *alldevs;
    char errbuf[PCAP_ERRBUF_SIZE];
    int x;

    x = PCAP.findalldevs(&alldevs, errbuf);
    if (x != -1) {
        const pcap_if_t *d;

        if (alldevs == NULL) {
            fprintf(stderr, "ERR:libpcap: no adapters found, are you sure you are root?\n");
        }
        /* Print the list */
        for (d = alldevs; d; d = PCAP.dev_next(d)) {
            if (index-- == 0)
                return PCAP.dev_name(d);
        }
        return 0;
    } else {
        return 0;
    }
}

/***************************************************************************
 * Some methods of transmit queue multiple packets in a buffer then
 * send all queued packets at once. At the end of a scan, we might have
 * some pending packets that haven't been transmitted yet. Therefore,
 * we'll have to flush them.
 ***************************************************************************/
//void
//rawsock_flush(struct Scan_Config *adapter)
//{
//    if (adapter->sendq) {
//        PCAP.sendqueue_transmit(adapter->pcap, adapter->sendq, 0);
//
//        /* Dude, I totally forget why this step is necessary. I vaguely
//         * remember there's a good reason for it though */
//        PCAP.sendqueue_destroy(adapter->sendq);
//        adapter->sendq =  PCAP.sendqueue_alloc(SENDQ_SIZE);
//    }
//
//}

/***************************************************************************
 * wrapper for libpcap's sendpacket
 *
 * PORTABILITY: WINDOWS and PF_RING
 * For performance, Windows and PF_RING can queue up multiple packets, then
 * transmit them all in a chunk. If we stop and wait for a bit, we need
 * to flush the queue to force packets to be transmitted immediately.
 ***************************************************************************/
int
rawsock_send_packet(pcap_t *adapter, const unsigned char *packet, unsigned length) {
    // windows的pcap才需要什么sendq linux不需要～
    return PCAP.sendpacket(adapter, packet, length);

}


/***************************************************************************
 ***************************************************************************/
int rawsock_recv_packet(
        pcap_t *pcap,
        unsigned *length,
        unsigned *secs,
        unsigned *usecs,
        const unsigned char **packet) {


    struct pcap_pkthdr hdr;

    *packet = PCAP.next(pcap, &hdr);
    *length = hdr.caplen;
    *secs = (unsigned) hdr.ts.tv_sec;
    *usecs = (unsigned) hdr.ts.tv_usec;


    return 0;
}


/***************************************************************************
 * Sends the TCP SYN probe packet.
 *
 * Step 1: format the packet
 * Step 2: send it in a portable manner
 ***************************************************************************/
void
rawsock_send_probe_ipv4(
        struct Adapter *adapter,
        ipv4address ip_them, unsigned port_them,
        ipv4address ip_me, unsigned port_me,
        unsigned seqno, unsigned flush,
        struct TemplateSet *tmplset) {
    unsigned char px[2048];
    size_t packet_length;

    /*
     * Construct the destination packet
     */
//    template_set_target_ipv4(tmplset, ip_them, port_them, ip_me, port_me, seqno,
//                             px, sizeof(px), &packet_length);

    /*
     * Send it
     */
    rawsock_send_packet(adapter->pcap, px, (unsigned) packet_length);
}

void
rawsock_send_probe_ipv6(
        struct Adapter *adapter,
        ipv6address ip_them, unsigned port_them,
        ipv6address ip_me, unsigned port_me,
        unsigned seqno, unsigned flush,
        struct TemplateSet *tmplset) {
    unsigned char px[2048];
    size_t packet_length;

    /*
     * Construct the destination packet
     */
//    template_set_target_ipv6(tmplset, ip_them, port_them, ip_me, port_me, seqno,
//                             px, sizeof(px), &packet_length);

    /*
     * Send it
     */
    rawsock_send_packet(adapter->pcap, px, (unsigned) packet_length);
}

/***************************************************************************
 * Used on Windows: network adapters have horrible names, so therefore we
 * use numeric indexes instead. You can which adapter you are looking for
 * by typing "--iflist" as an option.
 ***************************************************************************/
static int
is_numeric_index(const char *ifname) {
    int result = 1;
    int i;

    /* empty strings aren't numbers */
    if (ifname[0] == '\0')
        return 0;

    /* 'true' if all digits */
    for (i = 0; ifname[i]; i++) {
        char c = ifname[i];

        if (c < '0' || '9' < c)
            result = 0;
    }

    return result;
}


/***************************************************************************
 * Used on Windows: if the adapter name is a numeric index, convert it to
 * the full name.
 ***************************************************************************/
const char *
rawsock_win_name(const char *ifname) {
    if (is_numeric_index(ifname)) {
        const char *new_adapter_name;

        new_adapter_name = adapter_from_index(atoi(ifname));
        if (new_adapter_name)
            return new_adapter_name;
    }

    return ifname;
}


/***************************************************************************
 * Configure the socket to not capture transmitted packets. This is needed
 * because we transmit packets at a rate of millions per second, which will
 * overwhelm the receive thread.
 *
 * PORTABILITY: Windows doesn't seem to support this feature, so instead
 * what we do is apply a BPF filter to ignore the transmits, so that they
 * still get filtered at a low level.
 ***************************************************************************/
void
rawsock_ignore_transmits(struct Adapter *adapter, const char *ifname) {
    if (adapter->ring) {
        /* PORTABILITY: don't do anything for PF_RING, because it's
         * actually done when we create the adapter, because we can't
         * reconfigure the adapter after it's been activated. */
        return;
    }

    if (adapter->pcap) {
        int err;
        err = PCAP.setdirection(adapter->pcap, PCAP_D_IN);
        if (err) { ; //PCAP.perror(adapter->pcap, "if: pcap_setdirection(IN)");
        } else {
            LOG(2, "if:%s: not receiving transmits\n", ifname);
        }
    }
}

/***************************************************************************
 ***************************************************************************/
static void
rawsock_close_adapter(struct Adapter *adapter) {
    if (adapter->ring) {
        PFRING.close(adapter->ring);
    }
    if (adapter->pcap) {
        PCAP.close(adapter->pcap);
    }
    if (adapter->sendq) {
        PCAP.sendqueue_destroy(adapter->sendq);
    }

    free(adapter);
}

/***************************************************************************
 * Does the name look like a PF_RING DNA adapter? Common names are:
 * dna0
 * dna1
 * dna0@1
 *
 ***************************************************************************/
static int
is_pfring_dna(const char *name) {
    if (strlen(name) < 4)
        return 0;
    if (memcmp(name, "zc:", 3) == 0)
        return 1;
    if (memcmp(name, "dna", 3) != 0)
        return 0;

    name += 3;

    if (!isdigit(name[0] & 0xFF))
        return 0;
    while (isdigit(name[0] & 0xFF))
        name++;

    if (name[0] == '\0')
        return 1;

    if (name[0] != '@')
        return 0;
    else
        name++;

    if (!isdigit(name[0] & 0xFF))
        return 0;
    while (isdigit(name[0] & 0xFF))
        name++;

    if (name[0] == '\0')
        return 1;
    else
        return 0;
}


/***************************************************************************
 * for testing when two Windows adapters have the same name. Sometimes
 * the \Device\NPF_ string is prepended, sometimes not.
 ***************************************************************************/
int
rawsock_is_adapter_names_equal(const char *lhs, const char *rhs) {
    if (memcmp(lhs, "\\Device\\NPF_", 12) == 0)
        lhs += 12;
    if (memcmp(rhs, "\\Device\\NPF_", 12) == 0)
        rhs += 12;
    return strcmp(lhs, rhs) == 0;
}


/***************************************************************************
 ***************************************************************************/
int
rawsock_selftest() {

    return 0;
}


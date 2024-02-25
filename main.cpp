#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <WinSock2.h>
#include <memory>
#include <stdexcept>
#include <sstream>
#include <vector>
#include <map>
#include <thread>

// Link with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")


// Function for bug fixing: printing bytes

void printBytes(const u_char* data, int length) {
    for (int i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i] << " ";
        if ((i + 1) % 16 == 0) std::cout << std::endl; // Print a new line every 16 bytes
    }
    std::cout << std::endl;
}


// Unnecessary socket closing function

void close_all_sockets(std::map<u_short, SOCKET>* socky_mappy) {
    for (const auto& pair : *socky_mappy) {
        SOCKET sock = pair.second;
        closesocket(sock);
    }


}

// Create local raw socket to send a packet

SOCKET makeportsock(u_short port_numba) {
    // Create a raw socket to send packets to a different local port
    SOCKET sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (sockfd < 0) {
        std::cerr << "Error creating raw socket" << std::endl;
        return 1;
    }

    // Set up the destination address
    struct sockaddr_in destAddr;
    destAddr.sin_family = AF_INET;
    destAddr.sin_port = htons(port_numba); // Change this to the desired local port
    inet_pton(AF_INET, "127.0.0.1", &destAddr.sin_addr);

    return sockfd;
}



// Bash command executor and parser to find which ports are accessed by a process id

std::string exec(const char* cmd) {
    char buffer[128];
    std::string result = "";
    FILE* pipe = _popen(cmd, "r");
    if (!pipe) throw std::runtime_error("popen() failed!");
    try {

        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {

            //bug fixing
            //std::cout << buffer

            const char the_legit_letter_t[] = "T";
            if (buffer[2] == the_legit_letter_t[0]) {


                std::string input_lines = buffer;
                size_t colonPos = input_lines.find(':');
                if (colonPos != std::string::npos) {
                    // Extract the substring after the colon
                    std::string substring = input_lines.substr(colonPos + 1);



                    
                    // Trim leading whitespace
                    size_t start = substring.find_first_not_of(" \t\n\r");
                    if (start != std::string::npos) {
                        substring = substring.substr(start);

                    }
                    // Trim trailing whitespace
                    start = substring.find_first_of(" \t\n\r");
                    if (start != std::string::npos) {
                        substring = substring.substr(0, start);
                        result += substring;
                        result += "\n";
                    }
                }
            }


        }
    }
    catch (...) {
        _pclose(pipe);
        throw;
    }
    _pclose(pipe);
    return result;
}



//

int FINAL_TOUCHES_MAIN(std::string* port_capture) {
    char errbuf[PCAP_ERRBUF_SIZE];

    // Choose the interface you want to capture packets from
    const char* device = "\\_____________\\{________________}"; // Change this to the desired interface name

    // Open the selected network interface for capturing
    pcap_t* pcap = pcap_open_live(device, 65536, 1, 1000, errbuf);
    if (pcap == nullptr) {
        std::cerr << "Error opening interface: " << errbuf << std::endl;
        return 1;
    }





    //const char* filter_exp = "tcp port 80";
    struct bpf_program fp; 
    bpf_u_int32 net = 0;

    // Filtering for specific ports
    
    std::string filter_string = "tcp port " + *port_capture;
    const char* filter_char_pointer = filter_string.c_str();

    if (pcap_compile(pcap, &fp, filter_char_pointer, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter expression" << std::endl;
        return 1;
    }

    /*if (pcap_compile(pcap, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Error compiling filter expression" << std::endl;
        return 1;
    }*/

    if (pcap_setfilter(pcap, &fp) == -1) {
        std::cerr << "Error setting filter" << std::endl;
        return 1;
    }

   
    // Capture packets
    struct pcap_pkthdr* header;
    const char* data = nullptr;
    const u_char* u_char_ptr = reinterpret_cast<const u_char*>(data);
    


    //Here change the numbers at the end to the desired process id
    
    std::string output = exec("netstat -ano | find \"######\"");

    std::istringstream iss(output);

    std::vector<u_short> specific_ports;

    std::string line;

    while (std::getline(iss, line)) {
        unsigned short ushort_val = std::stoul(line);
        specific_ports.push_back(ushort_val);
    }



    std::map<u_short, SOCKET> port_sockets;

    // Creating a map of sockets to send packets to

    for (u_short port : specific_ports) {
        SOCKET sock = makeportsock(port);
        if (sock != INVALID_SOCKET) {
            port_sockets[port] = sock;
        }
    }


    // Capturing and sending packets

    while (int returnValue = pcap_next_ex(pcap, &header, &u_char_ptr) >= 0) {
        
        if (returnValue == 0) continue; // Timeout expired
        
        // Specified the length of the packets to filter out nonsense
        // Specified the length of the packets to filter out nonsense
        // Specified the length of the packets to filter out nonsense
        // Specified the length of the packets to filter out nonsense
        if (header->len > 60){
            std::cout << "Packet captured! Length: " << header->len << " bytes \n";
            // Send the captured packet to the local port using the raw socket
            for (const auto& pair : port_sockets) {
                u_short port = pair.first;
                SOCKET socky = pair.second;
                
                send(socky, data, header->len, 0);
            }

            
        }
    }


    pcap_close(pcap);
    close_all_sockets(&port_sockets);
    return 0;
}







int main() {

    //The process id of the process you want to capture traffic from not send to
    std::string capturing_from_text = exec("netstat -ano | find \"#########\"");

    std::istringstream iss(capturing_from_text);

    std::vector<std::string> capturing_from_ports;

    std::string capturing_from_line;


    // Creating a vector of ports that you want to capture from

    while (std::getline(iss, capturing_from_line)) {
        //unsigned short capturing_from_ushort_val = std::stoul(capturing_from_line);
        capturing_from_ports.push_back(capturing_from_line);
    }


    /*
    std::map<u_short, SOCKET> capturing_from_port_sockets;

    for (u_short capturing_from_ind_port : capturing_from_ports) {
        SOCKET sockap = makeportsock(capturing_from_ind_port);
        if (sockap != INVALID_SOCKET) {
            capturing_from_port_sockets[capturing_from_ind_port] = sockap;
        }
    }
    */



    std::vector<std::thread> threads;

    // Creating seperate threads to process each port that you capture from.

    for (auto& filter_exp : capturing_from_ports) {
        threads.emplace_back(std::thread(FINAL_TOUCHES_MAIN, &filter_exp));
    }

    for (auto& thread : threads) {
        thread.join();
    }
}
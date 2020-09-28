#include "snmptrap_client.hpp"
#include <iostream>
int main() {
    snmptrap_client client;
    client.set_peer_name("192.168.5.129:162");
    if (!client.init()) {
        std::cerr << "snmp client init failed." << std::endl;
        return -1;
    }
    std::cout << "ret code = " << client.send_cpu_used("99") << std::endl;
    std::cout << "ret code = " << client.send_storage_used("98") << std::endl;

    return 0;
}
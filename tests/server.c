#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>
#include <pcap.h>
#include <zmq.h>
#include <netinet/ip.h> // Для структуры IP
#include <arpa/inet.h>  // Для inet_ntoa

// Обработчик пакетов
void packetHandler(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
    const struct ip *ipHeader = (struct ip *)(packet + 14); // Пропускаем Ethernet заголовок

    // Получение информации о IP-адресах
    printf("Source IP: %s\n", inet_ntoa(ipHeader->ip_src));
    printf("Destination IP: %s\n", inet_ntoa(ipHeader->ip_dst));

    // Вывод размера заголовка IP-пакета
    printf("IP Header Size: %d bytes\n", ipHeader->ip_hl * 4);

    // Вывод Payload поля
    const u_char *payload = packet + 14 + (ipHeader->ip_hl * 4);
    int payloadLength = header->len - (14 + (ipHeader->ip_hl * 4));

    printf("Payload: ");
    for (int i = 0; i < payloadLength; ++i) {
        printf("%02x ", payload[i]);
    }
    printf("\n");
}

int main(void) {
    // Инициализация ZeroMQ
    void *context = zmq_ctx_new();
    void *responder = zmq_socket(context, ZMQ_REP);
    int rc = zmq_bind(responder, "tcp://*:5555");
    assert(rc == 0);
    
    // Инициализация pcap
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
        return 1;
    }

    // Используем первое устройство для захвата пакетов
    pcap_t *handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    
    if (handle == NULL) {
        fprintf(stderr, "Could not open device: %s\n", errbuf);
        return 2;
    }

    while (1) {
        char buffer[10];
        zmq_recv(responder, buffer, 10, 0);
        printf("Received Hello\n");

        // Захват пакета
        struct pcap_pkthdr header;
        const u_char *packet = pcap_next(handle, &header);
        
        if (packet != NULL) {
            packetHandler(NULL, &header, packet);
        }

        sleep(1); // Выполнение 'работы'
        zmq_send(responder, "World", 5, 0);
    }

    pcap_freealldevs(alldevs);
    zmq_close(responder);
    zmq_ctx_destroy(context);
    
    return 0;
}
#include "Message.h"
#include "PDUs.h"

int main() {
    struct sockaddr_in addr; 
    addr.sin_family = AF_INET; 
    addr.sin_port = htons(9999);
    addr.sin_addr.s_addr = htonl(INADDR_ANY); 

    int sock = socket(AF_INET, SOCK_DGRAM, 0); 
    socklen_t udp_socket_size = sizeof(addr);
    bind(sock, (struct sockaddr *)&addr, udp_socket_size);

    size_t buffer_size = 1024;
    uint8_t* buffer = calloc(1, sizeof(uint8_t)*buffer_size);
    int recv = recvfrom(sock, buffer, buffer_size, 0, (struct sockaddr *)&addr, &udp_socket_size);

    Message_t *message = 0;
    asn_dec_rval_t rval = asn_decode(0, ATS_BER, &asn_DEF_Message, (void **)&message, buffer, buffer_size);

    xer_fprint(stdout, &asn_DEF_Message, message);

    PDUs_t* pdu = 0;
    asn_dec_rval_t rval2 = asn_decode(0, ATS_BER, &asn_DEF_PDUs, (void **)&pdu, message->data.buf, message->data.size);

/*
    PDUs_t* pdu = decodePDUS();
    VarBindList_t var_bindings = pdu->choice.set_request.variable_bindings; 
    int var_list_size = var_bindings.list.count;
    VarBind_t* var_bind = var_bindings.list.array[0];
*/

    return 0;
}
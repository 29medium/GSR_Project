#include "SimpleSyntax.h"
#include "ObjectSyntax.h"
#include "ObjectName.h"
#include "VarBind.h"
#include "VarBindList.h"
#include "SetRequest-PDU.h"
#include "PDUs.h"
#include "ANY.h"
#include "Message.h"
#include "OCTET_STRING.h"

int main() {
    SimpleSyntax_t* simple;
    simple = calloc(1, sizeof(SimpleSyntax_t)); 
    simple->present = SimpleSyntax_PR_integer_value; 
    simple->choice.integer_value = 1;

    ObjectSyntax_t* object_syntax;
    object_syntax = calloc(1, sizeof(ObjectSyntax_t)); 
    object_syntax->present = ObjectSyntax_PR_simple; 
    object_syntax->choice.simple = *simple;

    ObjectName_t* object_name;
    object_name = calloc(1, sizeof(ObjectName_t)); 
    object_name->buf = "1.2.3.4";
    object_name->size = strlen(object_name->buf);

    VarBind_t* var_bind;
    var_bind = calloc(1, sizeof(VarBind_t)); 
    var_bind->name = *object_name; 
    var_bind->choice.present = choice_PR_value;
    var_bind->choice.choice.value = *object_syntax;

    VarBindList_t* varlist;
    varlist = calloc(1, sizeof(VarBindList_t));
    int r = ASN_SEQUENCE_ADD(&varlist->list, var_bind);

    SetRequest_PDU_t* setRequestPDU;
    setRequestPDU = calloc(1, sizeof(SetRequest_PDU_t)); 
    setRequestPDU->request_id = 1; 
    setRequestPDU->error_index = 0; 
    setRequestPDU->error_status = 0;
    setRequestPDU->variable_bindings = *varlist;

    PDUs_t *pdus;
    pdus = calloc(1, sizeof(PDUs_t)); 
    pdus->present = PDUs_PR_set_request;
    pdus->choice.set_request = *setRequestPDU;

    size_t buffer_size = 1024;
    uint8_t* buffer = calloc(1, sizeof(uint8_t)*buffer_size);

    asn_enc_rval_t ret = asn_encode_to_buffer(0, ATS_BER, &asn_DEF_PDUs, pdus, buffer, buffer_size);

    ANY_t* data;
    data = calloc(1, sizeof(ANY_t));
    data->buf = buffer;
    data->size = ret.encoded;

    OCTET_STRING_t* community;
    community = calloc(1, sizeof(OCTET_STRING_t));
    OCTET_STRING_fromBuf(community, "community", -1);

    Message_t* message;
    message = calloc(1, sizeof(Message_t)); 
    message->version = 2; 
    message->community = *community; 
    message->data = *data;  

    xer_fprint(stdout, &asn_DEF_Message, message);

    size_t buffer_final_size = 1024;
    uint8_t* buffer_final = calloc(1, sizeof(uint8_t)*buffer_final_size);

    asn_enc_rval_t ret2 = asn_encode_to_buffer(0, ATS_BER,
    &asn_DEF_Message, message, buffer_final, buffer_final_size);

    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(9999); 
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t udp_socket_size = sizeof(addr);

    int sent = sendto(sock, buffer_final, buffer_final_size, 0, (struct sockaddr *)&addr, udp_socket_size);

    return 0;
}
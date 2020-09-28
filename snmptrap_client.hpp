#pragma once
#include "net-snmp/net-snmp-config.h"
#include "net-snmp/net-snmp-includes.h"
#include <string.h>
#include <string>
static const oid OID_SYSUPTIME[] = { 1, 3, 6, 1, 2, 1, 1, 3, 0 };
static const oid OID_SNMPTRAP[] = { 1, 3, 6, 1, 6, 3, 1, 1, 4, 1, 0 };
static const oid OID_CPU_USED[] = { 1, 3, 6, 1, 4, 1, 2021, 11, 9, 0 };
static const oid OID_STORAGE_USED[] = { 1, 3, 6, 1, 2, 1, 25, 2, 3, 1, 6 };
enum ErrorType {
    NO_ERROR,
    SNMP_CREATE_PDU_ERROR,
    SNMP_ADD_VAR_OID_SYSUPTIME_ERROR,
    SNMP_ADD_VAR_OID_SNMPTRAP_ERROR,
    SNMP_ADD_VAR_OID_CPU_USED_ERROR,
    SNMP_ADD_VAR_OID_STORAGE_USED_ERROR,
    SNMP_SEND_TRAP_ERROR,
    UNKNOWN_TYPE_ERROR
};
enum SendType {
    SEND_LOCAL_CPU_USED,
    SEND_LOCAL_STORAGE_USED
};
class snmptrap_client {
public:
    snmptrap_client() {
        memset(&session_, 0, sizeof(session_));
        client_name_ = "snmpclient.";
        peername_ = "127.0.0.1:162";
        session_ptr_ = NULL;
    }
    virtual ~snmptrap_client() {
        if (session_ptr_ != NULL) {
            snmp_close(session_ptr_);
        }
        SOCK_CLEANUP;
        snmp_shutdown(client_name_);
    }
    inline bool init() {
        init_client();
        return init_session();
    }
    inline void set_client_name(const char *name) {
        client_name_ = name;
    }
    inline void set_peer_name(const char *name) {
        peername_ = name;
    }
    int send_cpu_used(const char *val) {
        return send_locale_oid("UCD-SNMP-MIB::ssCpuUser.0", val, SEND_LOCAL_CPU_USED);
    }
    int send_storage_used(const char *val) {
        return send_locale_oid("HOST-RESOURCES-MIB::hrStorage", val, SEND_LOCAL_STORAGE_USED);
    }
private:
    inline void init_client() {
        init_snmp(client_name_);
    }
    inline bool init_session() {
        static const char *community = "public";
        snmp_sess_init(&session_);
        session_.version = SNMP_VERSION_2c;
        session_.peername = (char *)peername_;
        session_.community = (unsigned char *)community;
        session_.community_len = strlen(community);
        session_.retries = 3;
        session_.timeout = 2000;
        session_ptr_ = snmp_open(&session_);
        return session_ptr_ != NULL;
    }
    int send_locale_oid(const char *key, const char *val, unsigned send_type) {
        netsnmp_pdu *pdu = snmp_pdu_create(SNMP_MSG_TRAP2);
        if (NULL == pdu) {
            return SNMP_CREATE_PDU_ERROR;
        }
        char sysuptime[64] = "";
        snprintf(sysuptime, sizeof(sysuptime), "%ld", get_uptime());
        if (snmp_add_var(pdu, OID_SYSUPTIME, OID_LENGTH(OID_SYSUPTIME), 't', sysuptime)) {
            snmp_free_pdu(pdu);
            return SNMP_ADD_VAR_OID_SYSUPTIME_ERROR;
        }
        if (snmp_add_var(pdu, OID_SNMPTRAP, OID_LENGTH(OID_SNMPTRAP), 'o', key)) {
            snmp_free_pdu(pdu);
            return SNMP_ADD_VAR_OID_SNMPTRAP_ERROR;
        }
        switch (send_type)
        {
        case SEND_LOCAL_CPU_USED:
            if (snmp_add_var(pdu, OID_CPU_USED, OID_LENGTH(OID_CPU_USED), 'i', val)) {
                snmp_free_pdu(pdu);
                return SNMP_ADD_VAR_OID_CPU_USED_ERROR;
            }
            break;
        case SEND_LOCAL_STORAGE_USED:
            if (snmp_add_var(pdu, OID_STORAGE_USED, OID_LENGTH(OID_STORAGE_USED), 'i', val)) {
                snmp_free_pdu(pdu);
                return SNMP_ADD_VAR_OID_STORAGE_USED_ERROR;
            }
            break;
        default:
            snmp_free_pdu(pdu);
            return UNKNOWN_TYPE_ERROR;
        }
        if (snmp_send(session_ptr_, pdu)) { // send ok snmp_send will free pdu
            return NO_ERROR;
        }
        // send error need to free pdu
        snmp_free_pdu(pdu);
        pdu = NULL;
        return SNMP_SEND_TRAP_ERROR;
    }
private:
    netsnmp_session session_;
    netsnmp_session *session_ptr_;
    const char *client_name_;
    const char *peername_;
};
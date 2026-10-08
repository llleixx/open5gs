/* DSCP classification wire-format and packet-matching regression tests. */
#include "ogs-nas-5gs.h"
#include "ogs-pfcp.h"
#include "ogs-sbi.h"
#include "core/abts.h"

static void dscp_wire_test(abts_case *tc, void *data)
{
    uint16_t value = 0;
    ogs_pcc_rule_t policy = {0}, copied = {0};
    OpenAPI_pcc_rule_t *sbi;
    OpenAPI_flow_information_t *info;
    ogs_ipfw_rule_t ipfw = {0};
    ogs_nas_qos_rule_t in = {0}, out[OGS_NAS_MAX_NUM_OF_QOS_RULE] = {0};
    ogs_nas_qos_rules_t encoded = {0};
    ogs_pfcp_sdf_filter_t sdf = {0}, parsed = {0};
    ogs_tlv_octet_t octet = {0};
    unsigned char buffer[256];
    int len;

    ABTS_INT_EQUAL(tc, OGS_OK, ogs_flow_parse_tos("b8fc", &value));
    ABTS_INT_EQUAL(tc, 0xb8fc, value);
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_flow_parse_tos("68FC", &value));
    ABTS_INT_EQUAL(tc, OGS_OK, ogs_flow_parse_tos("00fc", &value));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_flow_parse_tos("b800", &value));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_flow_parse_tos("b8fg", &value));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_flow_parse_tos("0xb8fc", &value));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_flow_parse_tos("b8", &value));
    ABTS_INT_EQUAL(tc, OGS_ERROR, ogs_flow_parse_tos(NULL, &value));

    policy.id = ogs_strdup("test-dscp");
    policy.num_of_flow = 1;
    policy.flow[0].direction = OGS_FLOW_UPLINK_ONLY;
    policy.flow[0].description = ogs_strdup("permit out tcp from 10.100.67.250 12165 to assigned");
    policy.flow[0].tos_traffic_class_presence = true;
    policy.flow[0].tos_traffic_class = 0xb8fc;
    OGS_STORE_PCC_RULE(&copied, &policy);
    ABTS_INT_EQUAL(tc, true, copied.flow[0].tos_traffic_class_presence);
    sbi = ogs_sbi_build_pcc_rule(&copied, 1);
    info = sbi->flow_infos->first->data;
    ABTS_STR_EQUAL(tc, "b8fc", info->tos_traffic_class);
    {
        cJSON *json = OpenAPI_pcc_rule_convertToJSON(sbi);
        OpenAPI_pcc_rule_t *roundtrip = OpenAPI_pcc_rule_parseFromJSON(json);
        OpenAPI_flow_information_t *flow = roundtrip->flow_infos->first->data;
        ABTS_STR_EQUAL(tc, "b8fc", flow->tos_traffic_class);
        OpenAPI_pcc_rule_free(roundtrip);
        cJSON_Delete(json);
    }
    ogs_sbi_free_pcc_rule(sbi);
    OGS_PCC_RULE_FREE(&copied);

    ABTS_INT_EQUAL(tc, OGS_OK, ogs_ipfw_compile_rule(&ipfw, policy.flow[0].description));
    ipfw.tos_traffic_class_presence = true;
    ipfw.tos_traffic_class = 0xb8fc;
    ogs_ipfw_rule_swap(&ipfw);
    ABTS_INT_EQUAL(tc, 0xb8fc, ipfw.tos_traffic_class);
    in.identifier = 2;
    in.code = OGS_NAS_QOS_CODE_CREATE_NEW_QOS_RULE;
    in.num_of_packet_filter = 1;
    in.pf[0].identifier = 1;
    in.pf[0].direction = OGS_NAS_QOS_DIRECTION_UPLINK;
    in.precedence = 1;
    in.flow.identifier = 2;
    ogs_pf_content_from_ipfw_rule(OGS_FLOW_UPLINK_ONLY, &in.pf[0].content, &ipfw, false);
    len = ogs_nas_build_qos_rules(&encoded, &in, 1);
    ABTS_INT_EQUAL(tc, OGS_OK, len);
    ABTS_TRUE(tc, encoded.length > 0);
    ABTS_INT_EQUAL(tc, 1, ogs_nas_parse_qos_rules(out, &encoded));
    {
        int last = out[0].pf[0].content.num_of_component - 1;
        ABTS_INT_EQUAL(tc, OGS_PACKET_FILTER_TOS_TRAFFIC_CLASS_TYPE, out[0].pf[0].content.component[last].type);
        ABTS_INT_EQUAL(tc, 0xb8, out[0].pf[0].content.component[last].tos.value);
        ABTS_INT_EQUAL(tc, 0xfc, out[0].pf[0].content.component[last].tos.mask);
    }
    ogs_free(encoded.buffer);

    sdf.fd = 1; sdf.ttc = 1;
    sdf.flow_description = policy.flow[0].description;
    sdf.flow_description_len = strlen(sdf.flow_description);
    sdf.tos_traffic_class = 0xb8fc;
    len = ogs_pfcp_build_sdf_filter(&octet, &sdf, buffer, sizeof(buffer));
    ABTS_TRUE(tc, len > 0);
    ABTS_INT_EQUAL(tc, len, ogs_pfcp_parse_sdf_filter(&parsed, &octet));
    ABTS_INT_EQUAL(tc, 0xb8fc, parsed.tos_traffic_class);
    ABTS_INT_EQUAL(tc, 0xb8, buffer[len-2]);
    ABTS_INT_EQUAL(tc, 0xfc, buffer[len-1]);
    OGS_PCC_RULE_FREE(&policy);
}

static void dscp_packet_test(abts_case *tc, void *data)
{
    ogs_pfcp_pdr_t pdr = {0};
    ogs_pfcp_rule_t rule = {0};
    uint8_t v4[40] = {0x45,0,0,40,0,0,0,0,64,6};
    uint8_t v6[60] = {0x60,0,0,0,0,20,6,64};
    int ipv6, mark, ecn;
    const int marks[] = {46,26,0,8};
    ogs_list_init(&pdr.rule_list);
    ogs_list_add(&pdr.rule_list, &rule);
    for (ipv6 = 0; ipv6 < 2; ipv6++) {
        uint8_t *packet = ipv6 ? v6 : v4;
        int plen = ipv6 ? sizeof(v6) : sizeof(v4);
        int hlen = ipv6 ? 40 : 20;
        ABTS_INT_EQUAL(tc, OGS_OK, ogs_ipfw_compile_rule(&rule.ipfw,
            ipv6 ? "permit out tcp from 2001:db8::250 12165 to assigned" :
                   "permit out tcp from 10.100.67.250 12165 to assigned"));
        ogs_ipfw_rule_swap(&rule.ipfw);
        rule.ipfw.tos_traffic_class_presence = true;
        rule.ipfw.tos_traffic_class = 0xb8fc;
        if (ipv6) {
            inet_pton(AF_INET6, "2001:db8::8", packet+8);
            inet_pton(AF_INET6, "2001:db8::250", packet+24);
        } else {
            inet_pton(AF_INET, "10.100.68.8", packet+12);
            inet_pton(AF_INET, "10.100.67.250", packet+16);
        }
        packet[hlen] = 0xc0; packet[hlen+1] = 0x01;
        packet[hlen+2] = 12165 >> 8; packet[hlen+3] = 12165 & 0xff;
        packet[hlen+12] = 0x50;
        for (mark=0;mark<4;mark++) for (ecn=0;ecn<4;ecn++) {
            uint8_t tos = (marks[mark]<<2)|ecn;
            ogs_pkbuf_t *buf = ogs_pkbuf_alloc(NULL, plen);
            if (ipv6) { packet[0]=0x60|(tos>>4); packet[1]=tos<<4; }
            else packet[1]=tos;
            ogs_pkbuf_put_data(buf, packet, plen);
            ABTS_INT_EQUAL(tc, mark==0,
                ogs_pfcp_pdr_rule_find_by_packet(&pdr,buf)==&rule);
            rule.ipfw.tos_traffic_class=0x68fc;
            ABTS_INT_EQUAL(tc, mark==1,
                ogs_pfcp_pdr_rule_find_by_packet(&pdr,buf)==&rule);
            rule.ipfw.tos_traffic_class_presence=false;
            ABTS_TRUE(tc, ogs_pfcp_pdr_rule_find_by_packet(&pdr,buf)==&rule);
            rule.ipfw.tos_traffic_class_presence=true;
            rule.ipfw.tos_traffic_class=0xb8fc;
            if (mark==0) {
                buf->data[hlen+3] ^= 1;
                ABTS_TRUE(tc, ogs_pfcp_pdr_rule_find_by_packet(&pdr,buf)==NULL);
                buf->data[hlen+3] ^= 1;
                buf->data[ipv6?39:19] ^= 1;
                ABTS_TRUE(tc, ogs_pfcp_pdr_rule_find_by_packet(&pdr,buf)==NULL);
            }
            ogs_pkbuf_free(buf);
        }
    }
}

abts_suite *test_dscp(abts_suite *suite)
{
    ogs_log_install_domain(&__ogs_pfcp_domain, "pfcp", OGS_LOG_ERROR);
    suite = ADD_SUITE(suite)
    abts_run_test(suite, dscp_wire_test, NULL);
    abts_run_test(suite, dscp_packet_test, NULL);
    return suite;
}

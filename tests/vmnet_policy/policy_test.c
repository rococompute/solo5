/*
 * Portable tests for the solo5-vmnet egress parser and filter.
 *
 * These tests compile and call tenders/vmnet/policy.h, the exact code the
 * launcher uses. They need no vmnet(3), no entitlement and no macOS; run
 * `make -C tests/vmnet_policy check` on any host.
 */
#include <stdio.h>
#include <string.h>

#include "policy.h"

static int checks, failures;

static void check(int ok, const char *what)
{
    checks++;
    if (!ok) {
        failures++;
        printf("FAIL: %s\n", what);
    }
}

static uint32_t netmask(unsigned bits)
{
    if (bits == 32)
        return UINT32_MAX;
    return bits ? (uint32_t)(UINT32_MAX << (32 - bits)) : 0;
}

static void add_rule(struct egress_policy *p, const char *arg)
{
    const char *error = NULL;
    if (!policy_parse_rule(p, arg, &error)) {
        failures++;
        printf("FAIL: could not add valid rule %s: %s\n", arg, error);
    }
}

static void parses(const char *arg, uint32_t net, unsigned bits,
        uint16_t port)
{
    struct egress_policy p = {0};
    const char *error = NULL;
    int ok = policy_parse_rule(&p, arg, &error);
    check(ok, arg);
    if (!ok) {
        printf("      unexpected error: %s\n", error);
        return;
    }
    check(p.nrules == 1, "one rule added");
    check(p.rules[0].net == net, "rule network");
    check(p.rules[0].mask == netmask(bits), "rule mask");
    check(p.rules[0].port == port, "rule port");
}

static void rejects(const char *arg)
{
    struct egress_policy p = {0};
    const char *error = NULL;
    int ok = policy_parse_rule(&p, arg, &error);
    check(!ok, arg);
    if (!ok)
        check(error != NULL && error[0] != 0, "error description");
    check(p.nrules == 0, "failed parse adds no rule");
}

/* Ethernet + IPv4 frame with an explicit fragment field, IHL and payload. */
static size_t frame_ipv4(uint8_t *f, uint8_t proto, uint32_t src,
        uint32_t dst, uint16_t frag, size_t ihl, const uint8_t *payload,
        size_t plen)
{
    memset(f, 0, 14 + ihl + plen);
    memset(f, 0xff, 6);      /* broadcast destination MAC */
    memset(f + 6, 0x02, 6);  /* arbitrary source MAC */
    f[12] = 0x08;
    f[13] = 0x00;
    uint8_t *ip = f + 14;
    size_t total = ihl + plen;
    ip[0] = (uint8_t)(0x40 | (ihl / 4));
    ip[2] = (uint8_t)(total >> 8);
    ip[3] = (uint8_t)total;
    ip[6] = (uint8_t)(frag >> 8);
    ip[7] = (uint8_t)frag;
    ip[8] = 64;
    ip[9] = proto;
    ip[12] = (uint8_t)(src >> 24);
    ip[13] = (uint8_t)(src >> 16);
    ip[14] = (uint8_t)(src >> 8);
    ip[15] = (uint8_t)src;
    ip[16] = (uint8_t)(dst >> 24);
    ip[17] = (uint8_t)(dst >> 16);
    ip[18] = (uint8_t)(dst >> 8);
    ip[19] = (uint8_t)dst;
    if (plen)
        memcpy(ip + ihl, payload, plen);
    return 14 + total;
}

static size_t transport(uint8_t *b, uint16_t sport, uint16_t dport)
{
    memset(b, 0, 8);
    b[0] = (uint8_t)(sport >> 8);
    b[1] = (uint8_t)sport;
    b[2] = (uint8_t)(dport >> 8);
    b[3] = (uint8_t)dport;
    b[4] = 0;
    b[5] = 8;
    return 8;
}

static size_t frame_udp(uint8_t *f, uint32_t src, uint32_t dst,
        uint16_t sport, uint16_t dport)
{
    uint8_t u[8];
    transport(u, sport, dport);
    return frame_ipv4(f, 17, src, dst, 0, 20, u, sizeof u);
}

static size_t frame_tcp(uint8_t *f, uint32_t src, uint32_t dst,
        uint16_t sport, uint16_t dport)
{
    uint8_t t[8];
    transport(t, sport, dport);
    return frame_ipv4(f, 6, src, dst, 0, 20, t, sizeof t);
}

static uint32_t ip4(unsigned a, unsigned b, unsigned c, unsigned d)
{
    return (a << 24) | (b << 16) | (c << 8) | d;
}

static void test_parser_valid(void)
{
    parses("203.0.113.0/24", ip4(203, 0, 113, 0), 24, 0);
    parses("203.0.113.7/24:443", ip4(203, 0, 113, 0), 24, 443);
    parses("0.0.0.0/0", 0, 0, 0);
    parses("255.255.255.255/32:65535", UINT32_MAX, 32, 65535);
    parses("192.0.2.1", ip4(192, 0, 2, 1), 32, 0);
    parses("10.1.2.3/8:1", ip4(10, 0, 0, 0), 8, 1);
    parses("172.16.5.5/31", ip4(172, 16, 5, 4), 31, 0);
    parses("198.51.100.9/30", ip4(198, 51, 100, 8), 30, 0);
}

static void test_parser_malformed(void)
{
    static const char *bad[] = {
        "",
        "/24",
        "1.2.3.4/",
        "1.2.3.4/ 8",
        "1.2.3.4/+8",
        "1.2.3.4/-1",
        "1.2.3.4/33",
        "1.2.3.4/4294967328",
        "1.2.3.4/999999999999999999999999",
        "1.2.3.4/24junk",
        "1.2.3.4/24/25",
        "1.2.3.4/24 ",
        "1.2.3.4:443xyz",
        "1.2.3.4:80/24",
        "1.2.3.4:",
        "1.2.3.4:0",
        "1.2.3.4:65536",
        "1.2.3.4:99999999999999999999",
        "1.2.3.4: 80",
        "1.2.3.4:+80",
        "1.2.3.4:-80",
        "1.2.3.4:80:90",
        ":80",
        "1.2.3",
        "1.2.3.4.5",
        "1.2.3.256",
        " 1.2.3.4",
        "1.2.3.4 ",
        "1.2.3.4/24:443x",
        "1.2.3.4:80 ",
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++)
        rejects(bad[i]);
}

static void test_parser_limits(void)
{
    struct egress_policy p = {0};
    const char *error = NULL;
    char too_long[80];

    memset(too_long, '1', sizeof too_long - 1);
    too_long[sizeof too_long - 1] = 0;
    check(!policy_parse_rule(&p, too_long, &error), "overlong rule rejected");
    check(p.nrules == 0, "overlong rule adds nothing");

    for (int i = 0; i < POLICY_MAX_RULES; i++)
        add_rule(&p, "10.0.0.1");
    check(p.nrules == POLICY_MAX_RULES, "maximum rules accepted");
    check(!policy_parse_rule(&p, "10.0.0.2", &error),
          "rule beyond maximum rejected");
    check(p.nrules == POLICY_MAX_RULES, "rejected rule did not grow policy");

    /* A failed parse must not disturb the rules already accepted. */
    struct egress_policy q = {0};
    add_rule(&q, "203.0.113.0/24:443");
    check(!policy_parse_rule(&q, "203.0.113.0/24:443junk", &error),
          "trailing garbage rejected");
    check(q.nrules == 1, "failed parse leaves earlier rule count");
    check(q.rules[0].net == ip4(203, 0, 113, 0) &&
          q.rules[0].mask == netmask(24) && q.rules[0].port == 443,
          "failed parse leaves earlier rule intact");
}

static void test_no_rules(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    size_t len = frame_udp(f, ip4(10, 0, 0, 2), ip4(8, 8, 8, 8), 1, 2);
    check(policy_allows(&p, f, len, 0), "no rules allows IPv4");
    check(policy_allows(&p, f, 0, 0), "no rules allows a runt");
}

static void test_ipv4_framing(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    add_rule(&p, "203.0.113.0/24");
    uint32_t allowed = ip4(203, 0, 113, 5);
    uint32_t denied = ip4(198, 51, 100, 5);

    size_t len = frame_udp(f, ip4(10, 0, 0, 2), allowed, 1234, 9);
    check(policy_allows(&p, f, len, 0), "IPv4 UDP to allowed CIDR");
    len = frame_udp(f, ip4(10, 0, 0, 2), denied, 1234, 9);
    check(!policy_allows(&p, f, len, 0), "IPv4 UDP to other CIDR");

    len = frame_tcp(f, ip4(10, 0, 0, 2), allowed, 1234, 443);
    check(policy_allows(&p, f, len, 0), "portless rule allows TCP");
    len = frame_ipv4(f, 1, ip4(10, 0, 0, 2), allowed, 0, 20, NULL, 0);
    check(policy_allows(&p, f, len, 0), "portless rule allows ICMP");

    /* ARP is always exempt. */
    memset(f, 0xff, 6);
    memset(f + 6, 0x02, 6);
    f[12] = 0x08;
    f[13] = 0x06;
    check(policy_allows(&p, f, 14, 0), "ARP frame allowed");
    check(policy_allows(&p, f, 42, 0), "padded ARP frame allowed");

    /* Runt and non-IPv4 frames. */
    len = frame_udp(f, ip4(10, 0, 0, 2), allowed, 1, 2);
    check(!policy_allows(&p, f, 13, 0), "13-byte frame denied");
    check(!policy_allows(&p, f, 14, 0), "IPv4 frame without header denied");
    check(!policy_allows(&p, f, 33, 0), "truncated IPv4 header denied");
    f[12] = 0x86;
    f[13] = 0xdd;
    check(!policy_allows(&p, f, 60, 0), "IPv6 ethertype denied");
    f[12] = 0x12;
    f[13] = 0x34;
    check(!policy_allows(&p, f, 60, 0), "unknown ethertype denied");
    f[12] = 0x81;
    f[13] = 0x00;
    check(!policy_allows(&p, f, 60, 0), "VLAN-tagged frame denied");
    f[12] = 0x00;
    f[13] = 0x3c;
    check(!policy_allows(&p, f, 60, 0), "802.3 length frame denied");

    /* The smallest possible IPv4 frame has a header but no transport
     * header; a destination rule still matches it. */
    len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), allowed, 0, 20, NULL, 0);
    check(len == 34, "minimum IPv4 frame length");
    check(policy_allows(&p, f, len, 0),
          "minimum IPv4 frame allowed by destination rule");

    /* Version and IHL sanity. */
    len = frame_udp(f, ip4(10, 0, 0, 2), allowed, 1, 2);
    f[14] = 0x65; /* version 6, IHL 5 */
    check(!policy_allows(&p, f, len, 0), "IPv6 version in IPv4 frame denied");
    f[14] = 0x44; /* version 4, IHL 16 */
    check(!policy_allows(&p, f, len, 0), "IHL below 20 denied");
    f[14] = 0x40; /* IHL 0 */
    check(!policy_allows(&p, f, len, 0), "IHL zero denied");

    /* IHL 24 (4 option bytes): ports live at byte 24, not 20. */
    {
        uint8_t u[8];
        transport(u, 1111, 2222);
        len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), allowed, 0, 24, u, sizeof u);
        check(policy_allows(&p, f, len, 0), "IPv4 options destination rule");
    }

    /* A frame whose IHL exceeds the captured length is denied. */
    {
        uint8_t u[8];
        transport(u, 1, 2);
        len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), allowed, 0, 60, u, sizeof u);
        check(policy_allows(&p, f, len, 0), "60-byte IHL with data");
        check(!policy_allows(&p, f, 14 + 20, 0), "IHL beyond frame denied");
    }
}

static void test_port_rules(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    add_rule(&p, "203.0.113.0/24:443");
    uint32_t dst = ip4(203, 0, 113, 5);

    size_t len = frame_tcp(f, ip4(10, 0, 0, 2), dst, 1234, 443);
    check(policy_allows(&p, f, len, 0), "TCP to allowed port");
    len = frame_udp(f, ip4(10, 0, 0, 2), dst, 1234, 443);
    check(policy_allows(&p, f, len, 0), "UDP to allowed port");
    len = frame_tcp(f, ip4(10, 0, 0, 2), dst, 1234, 80);
    check(!policy_allows(&p, f, len, 0), "TCP to other port");
    len = frame_ipv4(f, 1, ip4(10, 0, 0, 2), dst, 0, 20, NULL, 0);
    check(!policy_allows(&p, f, len, 0), "port rule denies ICMP");

    /* A truncated transport header cannot prove the port: deny. */
    len = frame_udp(f, ip4(10, 0, 0, 2), dst, 1234, 443);
    check(!policy_allows(&p, f, 14 + 20 + 2, 0),
          "truncated transport header denied by port rule");

    /* First fragment carries ports; later fragments do not. */
    {
        uint8_t u[8];
        transport(u, 1234, 443);
        len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), dst, 0x2000, 20, u,
                         sizeof u);
        check(policy_allows(&p, f, len, 0),
              "first fragment with allowed port");
        len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), dst, 0x00b9, 20, u,
                         sizeof u);
        check(!policy_allows(&p, f, len, 0),
              "non-first fragment denied by port rule");
    }
}

static void test_fragments(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    add_rule(&p, "203.0.113.0/24");
    uint32_t dst = ip4(203, 0, 113, 5);
    uint8_t data[8] = {0};

    size_t len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), dst, 0x2000, 20, data,
                            sizeof data);
    check(policy_allows(&p, f, len, 0),
          "first fragment allowed by destination rule");
    len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), dst, 0x00b9, 20, data,
                     sizeof data);
    check(policy_allows(&p, f, len, 0),
          "non-first fragment allowed by destination rule");
    len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), ip4(198, 51, 100, 5), 0x00b9,
                     20, data, sizeof data);
    check(!policy_allows(&p, f, len, 0),
          "non-first fragment outside rule denied");
    /* Last fragment (no MF, non-zero offset). */
    len = frame_ipv4(f, 17, ip4(10, 0, 0, 2), dst, 0x00b9, 20, data,
                     sizeof data);
    check(policy_allows(&p, f, len, 0), "last fragment allowed by destination");
}

static void test_dhcp_and_broadcast(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    uint32_t broadcast = UINT32_MAX;
    uint32_t server = ip4(192, 168, 64, 1);
    add_rule(&p, "198.51.100.0/24:80");

    /* DHCP DISCOVER/REQUEST: 0.0.0.0:68 -> 255.255.255.255:67. */
    size_t len = frame_udp(f, 0, broadcast, 68, 67);
    check(policy_allows(&p, f, len, 0), "DHCP broadcast discover allowed");

    /* DHCP renewal is normally unicast to the server. */
    len = frame_udp(f, ip4(192, 168, 64, 10), server, 68, 67);
    check(policy_allows(&p, f, len, 0), "DHCP unicast renewal allowed");

    /* Only DHCP may use the limited broadcast exemption. */
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 138, 137);
    check(!policy_allows(&p, f, len, 0), "NetBIOS broadcast denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 5353, 5353);
    check(!policy_allows(&p, f, len, 0), "mDNS multicast denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 1234, 67);
    check(!policy_allows(&p, f, len, 0),
          "broadcast to DHCP port from non-client port denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 68, 68);
    check(!policy_allows(&p, f, len, 0),
          "broadcast from DHCP port to other port denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 68, 53);
    check(!policy_allows(&p, f, len, 0),
          "broadcast from DHCP port to DNS port denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), ip4(192, 168, 64, 255), 138, 137);
    check(!policy_allows(&p, f, len, 0), "subnet broadcast denied");

    /* Explicitly allowed broadcasts still work through a rule. */
    struct egress_policy q = {0};
    add_rule(&q, "255.255.255.255/32");
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 138, 137);
    check(policy_allows(&q, f, len, 0),
          "broadcast allowed by explicit rule");
    struct egress_policy r = {0};
    add_rule(&r, "0.0.0.0/0:80");
    len = frame_tcp(f, ip4(192, 168, 64, 10), broadcast, 1234, 80);
    check(policy_allows(&r, f, len, 0),
          "broadcast to explicitly allowed port");
    len = frame_udp(f, ip4(192, 168, 64, 10), broadcast, 138, 137);
    check(!policy_allows(&r, f, len, 0),
          "broadcast to unlisted port still denied");
}

static void test_gateway_dns(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    uint32_t gateway = ip4(192, 168, 64, 1);
    add_rule(&p, "198.51.100.0/24:80");

    size_t len = frame_udp(f, ip4(192, 168, 64, 10), gateway, 1234, 53);
    check(policy_allows(&p, f, len, gateway),
          "DNS to gateway resolver allowed");
    len = frame_tcp(f, ip4(192, 168, 64, 10), gateway, 1234, 53);
    check(!policy_allows(&p, f, len, gateway),
          "TCP DNS to gateway not exempt");
    len = frame_udp(f, ip4(192, 168, 64, 10), gateway, 1234, 54);
    check(!policy_allows(&p, f, len, gateway),
          "non-DNS port to gateway denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), ip4(192, 168, 64, 2), 1234, 53);
    check(!policy_allows(&p, f, len, gateway),
          "DNS to non-gateway resolver denied");
    len = frame_udp(f, ip4(192, 168, 64, 10), gateway, 1234, 53);
    check(!policy_allows(&p, f, len, 0),
          "DNS exemption needs a known gateway");
}

static void test_multiple_rules(void)
{
    struct egress_policy p = {0};
    uint8_t f[128];
    add_rule(&p, "198.51.100.0/24:80");
    add_rule(&p, "203.0.113.0/24:443");

    size_t len = frame_tcp(f, ip4(10, 0, 0, 2), ip4(198, 51, 100, 7), 1, 80);
    check(policy_allows(&p, f, len, 0), "first rule matches");
    len = frame_tcp(f, ip4(10, 0, 0, 2), ip4(203, 0, 113, 7), 1, 443);
    check(policy_allows(&p, f, len, 0), "second rule matches");
    len = frame_tcp(f, ip4(10, 0, 0, 2), ip4(203, 0, 113, 7), 1, 80);
    check(!policy_allows(&p, f, len, 0), "port must match its own CIDR");
    len = frame_tcp(f, ip4(10, 0, 0, 2), ip4(198, 51, 100, 7), 1, 443);
    check(!policy_allows(&p, f, len, 0), "port must not cross CIDRs");

    /* 0.0.0.0/0 without a port is an explicit allow-all-IPv4 rule,
     * including broadcasts, but it does not make IPv6 pass. */
    struct egress_policy all = {0};
    add_rule(&all, "0.0.0.0/0");
    len = frame_udp(f, ip4(10, 0, 0, 2), UINT32_MAX, 138, 137);
    check(policy_allows(&all, f, len, 0),
          "allow-all rule permits limited broadcast");
    len = frame_udp(f, ip4(10, 0, 0, 2), ip4(8, 8, 8, 8), 1, 2);
    f[12] = 0x86;
    f[13] = 0xdd;
    check(!policy_allows(&all, f, len, 0),
          "allow-all IPv4 rule still denies IPv6");
}

int main(void)
{
    test_parser_valid();
    test_parser_malformed();
    test_parser_limits();
    test_no_rules();
    test_ipv4_framing();
    test_port_rules();
    test_fragments();
    test_dhcp_and_broadcast();
    test_gateway_dns();
    test_multiple_rules();

    if (failures) {
        printf("FAILED: %d of %d checks\n", failures, checks);
        return 1;
    }
    printf("PASS: %d checks\n", checks);
    return 0;
}

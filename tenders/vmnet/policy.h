/* Portable egress policy for solo5-vmnet. Same license as Solo5.
 *
 * This header contains the complete production parser and frame filter so
 * that the launcher and a host-independent test harness exercise exactly the
 * same code. It has no vmnet(3), dispatch(3) or macOS dependencies.
 */
#ifndef SOLO5_VMNET_POLICY_H
#define SOLO5_VMNET_POLICY_H

#include <arpa/inet.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define POLICY_MAX_RULES 64

struct policy_rule {
    uint32_t net, mask; /* host byte order */
    uint16_t port;      /* 0: any */
};

struct egress_policy {
    struct policy_rule rules[POLICY_MAX_RULES];
    int nrules;
};

/*
 * Parse a decimal number consisting only of digits. Rejects an empty string,
 * signs, whitespace, trailing characters and values greater than max.
 */
static bool policy_parse_number(const char *s, unsigned long max,
        unsigned long *value)
{
    unsigned long v = 0;
    if (*s == 0)
        return false;
    for (; *s; s++) {
        if (*s < '0' || *s > '9')
            return false;
        unsigned digit = (unsigned)(*s - '0');
        if (v > (max - digit) / 10)
            return false;
        v = v * 10 + digit;
    }
    *value = v;
    return true;
}

/*
 * Parse the argument of --allow=CIDR[:PORT] (the option name is not part of
 * arg). The accepted grammar is exactly:
 *
 *     A.B.C.D[/PREFIX][:PORT]
 *
 * with a dotted-quad IPv4 address, PREFIX in 0..32 and PORT in 1..65535.
 * Numbers are decimal digits only; any other byte, including whitespace,
 * signs and trailing garbage, is an error. On error returns false and sets
 * *error to a static description. A failed parse adds no rule.
 */
static bool policy_parse_rule(struct egress_policy *p, const char *arg,
        const char **error)
{
    char buf[64];
    char *port, *slash;
    unsigned long bits = 32, portnum = 0;
    struct in_addr a;
    struct policy_rule *r;

    if (p->nrules == POLICY_MAX_RULES) {
        *error = "too many rules";
        return false;
    }
    if (strlen(arg) >= sizeof buf) {
        *error = "rule too long";
        return false;
    }
    strcpy(buf, arg);

    port = strchr(buf, ':');
    if (port) {
        if (strchr(port + 1, ':')) {
            *error = "bad port";
            return false;
        }
        *port++ = 0;
    }
    slash = strchr(buf, '/');
    if (slash) {
        if (strchr(slash + 1, '/')) {
            *error = "bad prefix length";
            return false;
        }
        *slash++ = 0;
    }
    if (inet_pton(AF_INET, buf, &a) != 1) {
        *error = "bad IPv4 address";
        return false;
    }
    if (slash && !policy_parse_number(slash, 32, &bits)) {
        *error = "bad prefix length";
        return false;
    }
    if (port && (!policy_parse_number(port, 65535, &portnum) || portnum == 0)) {
        *error = "bad port";
        return false;
    }

    r = &p->rules[p->nrules];
    r->mask = bits == 32 ? UINT32_MAX
             : bits == 0  ? 0
             : (uint32_t)(UINT32_MAX << (32 - bits));
    r->net = ntohl(a.s_addr) & r->mask;
    r->port = (uint16_t)portnum;
    p->nrules++;
    return true;
}

/*
 * Egress policy. Returns true if the frame the guest sent may go out.
 *
 * With no rules all egress is allowed. Otherwise ARP and IPv4 are considered;
 * every other ethertype is denied. The documented exemptions are DHCP client
 * messages (UDP 68 -> 67, both limited broadcast and unicast renewal) and DNS
 * to the vmnet gateway's resolver. A limited broadcast is exempt only as
 * part of that DHCP exchange, not for arbitrary UDP.
 */
static bool policy_allows(const struct egress_policy *p, const uint8_t *f,
        size_t len, uint32_t gateway_ip)
{
    if (p->nrules == 0)
        return true;
    if (len < 14)
        return false;
    uint16_t type = (uint16_t)(f[12] << 8 | f[13]);
    if (type == 0x0806) /* ARP */
        return true;
    if (type != 0x0800) /* IPv6 and anything else: denied */
        return false;
    if (len < 14 + 20)
        return false;
    const uint8_t *ip = f + 14;
    size_t ihl = (size_t)(ip[0] & 0x0f) * 4;
    if ((ip[0] >> 4) != 4 || ihl < 20 || len < 14 + ihl)
        return false;
    uint8_t proto = ip[9];
    uint32_t dst = (uint32_t)ip[16] << 24 | (uint32_t)ip[17] << 16 |
                   (uint32_t)ip[18] << 8 | ip[19];
    uint16_t sport = 0, dport = 0;
    /* Only the first fragment carries the transport header. Later fragments
     * have no ports, so port-specific rules deny them (fail closed). */
    bool first_fragment = ((ip[6] & 0x1f) | ip[7]) == 0;
    bool ports = (proto == 6 || proto == 17) && first_fragment &&
                 len >= 14 + ihl + 4;
    if (ports) {
        sport = (uint16_t)(ip[ihl] << 8 | ip[ihl + 1]);
        dport = (uint16_t)(ip[ihl + 2] << 8 | ip[ihl + 3]);
    }

    /* DHCP client traffic: 68 -> 67. DISCOVER/REQUEST use the limited
     * broadcast address; renewal is normally unicast to the server. */
    if (proto == 17 && sport == 68 && dport == 67)
        return true;
    /* DNS to the vmnet gateway's resolver. */
    if (gateway_ip && dst == gateway_ip && proto == 17 && dport == 53)
        return true;

    for (int i = 0; i < p->nrules; i++) {
        if ((dst & p->rules[i].mask) != p->rules[i].net)
            continue;
        if (p->rules[i].port == 0)
            return true;
        if (ports && dport == p->rules[i].port)
            return true;
    }
    return false;
}

#endif

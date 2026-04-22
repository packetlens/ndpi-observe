/* SPDX-License-Identifier: Apache-2.0
 * Lightweight IP→hostname cache populated from observed DNS A responses.
 * Used as fallback when TLS SNI is unavailable (reused HTTP/2 connections).
 */
#ifndef NDPI_DNS_CACHE_H
#define NDPI_DNS_CACHE_H

#include <stdint.h>
#include <string.h>
#include <time.h>

#define DNS_CACHE_SIZE 512  /* must be power of 2 */

typedef struct {
    uint32_t ip;
    uint32_t expires;       /* unix timestamp */
    char     hostname[80];
} dns_cache_entry_t;

typedef struct {
    dns_cache_entry_t entries[DNS_CACHE_SIZE];
} dns_cache_t;

static inline uint32_t _dns_hash(uint32_t ip)
{
    ip ^= ip >> 16;
    ip *= 0x45d9f3bu;
    ip ^= ip >> 16;
    return ip & (DNS_CACHE_SIZE - 1);
}

static inline void dns_cache_insert(dns_cache_t *c, uint32_t ip,
                                     const char *name, uint32_t ttl)
{
    uint32_t idx = _dns_hash(ip);
    c->entries[idx].ip      = ip;
    c->entries[idx].expires = (uint32_t)time(NULL) + (ttl > 300 ? 300 : ttl);
    strncpy(c->entries[idx].hostname, name, sizeof(c->entries[idx].hostname) - 1);
    c->entries[idx].hostname[sizeof(c->entries[idx].hostname) - 1] = '\0';
}

static inline const char *dns_cache_lookup(dns_cache_t *c, uint32_t ip)
{
    uint32_t idx = _dns_hash(ip);
    dns_cache_entry_t *e = &c->entries[idx];
    if (e->ip == ip && e->hostname[0] && (uint32_t)time(NULL) < e->expires)
        return e->hostname;
    return NULL;
}

/* Parse a DNS response from raw IPv4 packet data and insert A records.
 * pkt points to the IPv4 header; pkt_len is the captured length. */
static inline void dns_cache_update(dns_cache_t *c,
                                     const uint8_t *pkt, uint32_t pkt_len)
{
    /* Need at least IP(20) + UDP(8) + DNS header(12) */
    if (pkt_len < 40) return;

    uint8_t ihl = (pkt[0] & 0xf) * 4;
    if (ihl < 20 || pkt_len < (uint32_t)(ihl + 8 + 12)) return;

    const uint8_t *dns     = pkt + ihl + 8;  /* DNS payload */
    uint32_t       dns_len = pkt_len - ihl - 8;

    uint16_t flags   = (uint16_t)((dns[2] << 8) | dns[3]);
    uint16_t qdcount = (uint16_t)((dns[4] << 8) | dns[5]);
    uint16_t ancount = (uint16_t)((dns[6] << 8) | dns[7]);

    /* Must be a standard query response with at least one answer */
    if (!(flags & 0x8000) || ancount == 0 || qdcount == 0) return;

    /* Extract query name from question section (offset 12) */
    char     qname[80] = "";
    uint32_t npos = 0;
    uint32_t off  = 12;
    while (off < dns_len) {
        uint8_t llen = dns[off++];
        if (llen == 0) break;
        if ((llen & 0xC0) == 0xC0) { off++; break; } /* pointer — ignore */
        if (npos > 0 && npos < sizeof(qname) - 1) qname[npos++] = '.';
        for (uint8_t i = 0; i < llen && off < dns_len && npos < sizeof(qname)-1; i++)
            qname[npos++] = (char)dns[off++];
    }
    qname[npos] = '\0';
    if (!qname[0]) return;

    /* Skip remaining questions */
    for (uint16_t q = 1; q < qdcount && off < dns_len; q++) {
        while (off < dns_len) {
            uint8_t llen = dns[off];
            if (llen == 0) { off++; break; }
            if ((llen & 0xC0) == 0xC0) { off += 2; break; }
            off += 1 + llen;
        }
        off += 4; /* QTYPE + QCLASS */
    }
    off += 4; /* first question's QTYPE + QCLASS */

    /* Parse answer records */
    for (uint16_t a = 0; a < ancount && off + 10 <= dns_len; a++) {
        /* Skip answer NAME (usually a pointer back to question) */
        if (off < dns_len && (dns[off] & 0xC0) == 0xC0) {
            off += 2;
        } else {
            while (off < dns_len) {
                uint8_t llen = dns[off];
                if (llen == 0) { off++; break; }
                if ((llen & 0xC0) == 0xC0) { off += 2; break; }
                off += 1 + llen;
            }
        }
        if (off + 10 > dns_len) break;

        uint16_t rtype    = (uint16_t)((dns[off]   << 8) | dns[off+1]);
        uint32_t ttl      = ((uint32_t)dns[off+4] << 24) | ((uint32_t)dns[off+5] << 16)
                          | ((uint32_t)dns[off+6] <<  8) |  (uint32_t)dns[off+7];
        uint16_t rdlength = (uint16_t)((dns[off+8] << 8) | dns[off+9]);
        off += 10;
        if (off + rdlength > dns_len) break;

        if (rtype == 1 && rdlength == 4) {
            uint32_t ip;
            memcpy(&ip, dns + off, 4);
            dns_cache_insert(c, ip, qname, ttl);
        }
        off += rdlength;
    }
}

#endif /* NDPI_DNS_CACHE_H */

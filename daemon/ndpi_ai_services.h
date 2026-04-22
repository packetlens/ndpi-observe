/* SPDX-License-Identifier: Apache-2.0
 * SNI-based AI service detection.
 * All major AI services use HTTPS/TLS — payload is encrypted, but the TLS
 * ClientHello SNI field is plaintext and already extracted by nDPI.
 */
#ifndef NDPI_AI_SERVICES_H
#define NDPI_AI_SERVICES_H
#include <stdint.h>
#include <string.h>

/* Custom protocol IDs above nDPI's max (281). Within the [512] array bounds. */
#define NDPI_APP_CLAUDE      300
#define NDPI_APP_CHATGPT     301
#define NDPI_APP_GEMINI      302
#define NDPI_APP_COPILOT     303
#define NDPI_APP_PERPLEXITY  304
#define NDPI_APP_GROK        305
#define NDPI_APP_MISTRAL     306
/* MCP: Model Context Protocol over SSE — detected by ML traffic shape, not SNI */
#define NDPI_APP_MCP         307

static inline const char *ndpi_ai_app_name(uint16_t id)
{
    switch (id) {
        case NDPI_APP_CLAUDE:     return "Claude";
        case NDPI_APP_CHATGPT:    return "ChatGPT";
        case NDPI_APP_GEMINI:     return "Gemini";
        case NDPI_APP_COPILOT:    return "Copilot";
        case NDPI_APP_PERPLEXITY: return "Perplexity";
        case NDPI_APP_GROK:       return "Grok";
        case NDPI_APP_MISTRAL:    return "Mistral";
        case NDPI_APP_MCP:        return "MCP";
        default:                  return NULL;
    }
}

static inline uint16_t match_ai_service(const char *sni)
{
    static const struct { const char *domain; uint16_t id; } t[] = {
        { "anthropic.com",                     NDPI_APP_CLAUDE     },
        { "claude.ai",                         NDPI_APP_CLAUDE     },
        { "openai.com",                        NDPI_APP_CHATGPT    },
        { "chatgpt.com",                       NDPI_APP_CHATGPT    },
        { "oai.azure.com",                     NDPI_APP_CHATGPT    },
        { "gemini.google.com",                 NDPI_APP_GEMINI     },
        { "generativelanguage.googleapis.com", NDPI_APP_GEMINI     },
        { "aistudio.google.com",               NDPI_APP_GEMINI     },
        { "copilot.microsoft.com",             NDPI_APP_COPILOT    },
        { "perplexity.ai",                     NDPI_APP_PERPLEXITY },
        { "grok.x.ai",                         NDPI_APP_GROK       },
        { "api.x.ai",                          NDPI_APP_GROK       },
        { "mistral.ai",                        NDPI_APP_MISTRAL    },
        { NULL, 0 }
    };
    for (int i = 0; t[i].domain; i++)
        if (strstr(sni, t[i].domain))
            return t[i].id;
    return 0;
}

#endif /* NDPI_AI_SERVICES_H */

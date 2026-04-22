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
#define NDPI_APP_MCP            307
/* MCP sub-types: ML detects SSE pattern, SNI identifies the specific service */
#define NDPI_APP_GITHUB_MCP     308  /* api.github.com / api.githubcopilot.com */
#define NDPI_APP_CLAUDE_MCP     309  /* api.anthropic.com / claude.ai           */
#define NDPI_APP_ASANA_MCP      310  /* mcp.asana.com                           */
#define NDPI_APP_GITLAB_MCP     311  /* gitlab.com                              */
#define NDPI_APP_LINEAR_MCP     312  /* mcp.linear.app                          */
#define NDPI_APP_GREPTILE_MCP   313  /* api.greptile.com                        */
#define NDPI_APP_MEDIUM_MCP     314  /* api.medium.com                          */
#define NDPI_APP_CLOUDFLARE_MCP 315  /* cloudflare.com (Workers AI/Cloudflare)  */

static inline const char *ndpi_ai_app_name(uint16_t id)
{
    switch (id) {
        case NDPI_APP_CLAUDE:         return "Claude";
        case NDPI_APP_CHATGPT:        return "ChatGPT";
        case NDPI_APP_GEMINI:         return "Gemini";
        case NDPI_APP_COPILOT:        return "Copilot";
        case NDPI_APP_PERPLEXITY:     return "Perplexity";
        case NDPI_APP_GROK:           return "Grok";
        case NDPI_APP_MISTRAL:        return "Mistral";
        case NDPI_APP_MCP:            return "MCP";
        case NDPI_APP_GITHUB_MCP:     return "Github_MCP";
        case NDPI_APP_CLAUDE_MCP:     return "Claude_MCP";
        case NDPI_APP_ASANA_MCP:      return "Asana_MCP";
        case NDPI_APP_GITLAB_MCP:     return "Gitlab_MCP";
        case NDPI_APP_LINEAR_MCP:     return "Linear_MCP";
        case NDPI_APP_GREPTILE_MCP:   return "Greptile_MCP";
        case NDPI_APP_MEDIUM_MCP:     return "Medium_MCP";
        case NDPI_APP_CLOUDFLARE_MCP: return "Cloudflare_MCP";
        default:                       return NULL;
    }
}

/* Called when ML decides a flow is MCP — map SNI to the specific service. */
static inline uint16_t match_mcp_service(const char *sni)
{
    if (!sni || !sni[0]) return NDPI_APP_MCP;
    static const struct { const char *domain; uint16_t id; } t[] = {
        { "github.com",         NDPI_APP_GITHUB_MCP     },
        { "githubcopilot.com",  NDPI_APP_GITHUB_MCP     },
        { "anthropic.com",      NDPI_APP_CLAUDE_MCP     },
        { "claude.ai",          NDPI_APP_CLAUDE_MCP     },
        { "asana.com",          NDPI_APP_ASANA_MCP      },
        { "gitlab.com",         NDPI_APP_GITLAB_MCP     },
        { "linear.app",         NDPI_APP_LINEAR_MCP     },
        { "greptile.com",       NDPI_APP_GREPTILE_MCP   },
        { "medium.com",         NDPI_APP_MEDIUM_MCP     },
        { "cloudflare.com",     NDPI_APP_CLOUDFLARE_MCP },
        { NULL, 0 }
    };
    for (int i = 0; t[i].domain; i++)
        if (strstr(sni, t[i].domain))
            return t[i].id;
    return NDPI_APP_MCP;
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

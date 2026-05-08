# OpenClaw Syncralis 🌐⚙️


An industry-grade, highly secure Model Context Protocol (MCP) server for OpenClaw. 

Syncralis provides load-balanced web searching, secure file downloads, and mobile-ready external file sharing, built on a hardened, hybrid architecture.


## 🚀 Key Features

***Stateless File Sharing:** Securely generates public Ngrok download links for files inside your workspace.

***Load-Balanced Web Search:** Intelligently alternates between Tavily and Brave Search APIs to prevent rate-limiting and ensure high availability.

***Secure File Downloads:** Downloads files directly to your workspace with strict MIME-type enforcement and streaming size limits to prevent DoS attacks.

***Path Boundary Enforcement:** Cryptographically verifies all file requests to prevent directory traversal attacks outside the designated workspace.


## 🔑 Prerequisites & Free Tiers

Syncralis relies on three external services. Each of these providers offers a generous free tier for developers (subject to their respective Terms and Conditions):

***Ngrok:** Provides the secure public tunnel for file downloads. Claim your free static domain at [https://ngrok.com](https://ngrok.com).

***Tavily API:** Provides AI-optimized web search results. Get your API key at [https://tavily.com](https://tavily.com).

***Brave Search API:** Provides the fallback web search index. Get your API key at [https://brave.com/search/api/](https://brave.com/search/api/).


## 📦 Installation


Install the package globally via your terminal:

```bash

npm install -g openclaw-syncralis

# OR via ClawHub: clawhub package install openclaw-syncralis

# OR via Openclaw: openclaw plugins install clawhub:openclaw-syncralis

```

### 🔑 Authentication
Before configuring the server, authenticate your local environment with the registry to ensure a secure handshake:

```bash

clawhub login pslkk/openclaw-syncralis

```


## ⚙️ Configuration & Deployment


Syncralis is designed as a hybrid tool. It works perfectly on your native operating system (Windows/Mac/Linux) or securely inside a Dockerized environment. 


#### The Workspace Directory (`WORKSPACE_DIR`):

The gateway needs a secure folder to store and manage files. We have designed this to be fully automated, but flexible for power users:

***Native / Default Install (Recommended):** Leave `WORKSPACE_DIR=` completely empty (or omit it). The gateway will automatically detect your OS and securely store files in your native home directory: `~/.openclaw/workspace`.

***Docker / Custom Environments:** If you are running OpenClaw inside a custom Docker container or want to force the gateway to use a specific volume mount, define the absolute path here:
`WORKSPACE_DIR=/custom/path/to/workspace`


### Choose the deployment method that matches your OpenClaw setup below:

### Option 1: Native NPM Setup (Without Docker)

When running OpenClaw natively on your host machine, Syncralis spins up a secure local HTTP server bound strictly to localhost.


1. Open a new terminal window and run Ngrok to expose the default port:

   *Note: For a production setup, we highly recommend using your static URL from the Ngrok dashboard so your tunnel never changes.*

  ```bash

  # 1. Authenticate your terminal (Run this once)
  ngrok config add-authtoken your_ngrok_token_here

  # 2. Start the tunnel using your static URL (Recommended)
  ngrok http --url your-custom-url.ngrok-free.app 8080

  # Or, using a dynamic URL (Testing only)
  ngrok http 8080

  ```

2. Add the generated Ngrok URL to your OpenClaw configuration generally inside (/home/node/.openclaw/openclaw.json):

  ```json

  "mcp": {
    "servers": {
      "syncralis": {
        "command": "openclaw-syncralis",
        "env": {
          "NODE_ENV": "production",
          "FILE_SERVER_HOST": "127.0.0.1",
          "WORKSPACE_DIR": "C:/custom/path/to/workspace", # Not-Mandatory in native Openclaw setup
          "PUBLIC_TUNNEL_URL": "https://your-ngrok-url.ngrok-free.app",
          "URL_SIGNING_SECRET": "your_custom_32_character_secret_here",
          "TAVILY_API_KEY": "your_tavily_key",
          "BRAVE_API_KEY": "your_brave_key"
        }
      }
    }
  }

  ```


### Option 2: Docker Environment Setup (Recommended for Production)

OpenClaw often executes tools as ephemeral child processes. In a containerized setup, it is highly recommended to run openclaw alongside Ngrok to serve the workspace volume 24/7. This guarantees your download links remain active even after the MCP process shuts down.


1. Configure your `openclaw.json` generally inside (/home/node/.openclaw/openclaw.json):

  ```json

  "mcp": {
    "servers": {
      "syncralis": {
        "command": "openclaw-syncralis",
        "env": {
          "NODE_ENV": "production",
          "FILE_SERVER_HOST": "0.0.0.0",
          "WORKSPACE_DIR": "C:/custom/path/to/workspace", # Same path add in docker-compose.yml under volumes
          "PUBLIC_TUNNEL_URL": "https://your-static-domain.ngrok-free.app",
          "URL_SIGNING_SECRET": "your_custom_32_character_secret_here",
          "TAVILY_API_KEY": "your_tavily_key",
          "BRAVE_API_KEY": "your_brave_key"
        }
      }
    }
  }

  ```


2. ### 🐳 Complete Docker Compose (Just an example only)


If you are running OpenClaw entirely inside Docker, here is a complete, production-ready `docker-compose.yml` template to get Syncralis and Ngrok running together seamlessly. 


```yaml

version: '3.8'

networks:
 mcp_network:
   driver: bridge

services:
 # Your main OpenClaw instance
 openclaw_gateway:
   image: ghcr.io/openclaw/openclaw:latest # Replace with your actual OpenClaw image or version
   container_name: openclaw_gateway
   restart: unless-stopped
   networks:
     - mcp_network
   ports:
     - "127.0.0.1:18789:18789"
   extra_hosts:
     - "host.docker.internal:host-gateway"
   volumes:
     - ./claw_data:/home/node/.openclaw:rw
     - # Your config file
     - /custom/path/to/workspace:/home/.openclaw/workspace:rw
   environment:
     - FILE_SERVER_HOST=0.0.0.0
     - FILE_SERVER_PORT=8080
     - PUBLIC_TUNNEL_URL=https://<your-custom-domain>.ngrok-free.app
     - TAVILY_API_KEY=${TAVILY_API_KEY}
     - BRAVE_API_KEY=${BRAVE_API_KEY}
   deploy:
     resources:
       limits:
         cpus: '2.0' # Hard cap: Cannot exceed 2 CPU cores
         memory: 2G
       reservations:
         memory: 512M

   logging:
     driver: "json-file"
     options:
       max-size: "10m"
       max-file: "5"
       compress: "true"

   healthcheck:
     test: ["CMD", "curl", "-f", "http://localhost:18789"]
     interval: 30s
     timeout: 10s
     retries: 3
     start_period: 40s

 # The Ngrok tunnel pointing to Syncralis's internal file server

 ngrok_tunnel:

   image: ngrok/ngrok:latest
   container_name: ngrok_tunnel
   restart: unless-stopped
   networks:
     - mcp_network
   command: http openclaw_gateway:8080 --url=https://<your-custom-domain>.ngrok-free.app --log=stdout
   environment:
     - NGROK_AUTHTOKEN=${NGROK_AUTHTOKEN}
   depends_on:
     openclaw_gateway:
       condition: service_healthy

```


## 🛡️ Security Parameters

* `MAX_QUERY_LENGTH`: Defaults to 2000 characters.

* `TIMEOUT_MS`: Defaults to 10000ms (10 seconds) to prevent hung API calls.

**Size Limits:** Syncralis enforces a hard limit of `50MB` for all file reads and downloads to prevent memory exhaustion. 



## 💬 Usage Examples (Prompts)

Once connected, you can ask your OpenClaw agent to perform complex I/O tasks:

**"Search the web for the latest advancements in solid-state batteries."*

**"Download the PDF from \[URL] and save it as `report.pdf`."*

**"Generate a mobile download link for `report.pdf`."*



---

*Built for resilient, secure agentic workflows.*


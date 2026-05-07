\# OpenClaw Syncralis 🌐⚙️



An industry-grade, highly secure Model Context Protocol (MCP) server for OpenClaw. 

Syncralis provides load-balanced web searching, secure file downloads, and mobile-ready external file sharing, built on a hardened, hybrid architecture.



\## 🚀 Key Features

\* \*\*Stateless File Sharing:\*\* Securely generates public Ngrok download links for files inside your workspace.

\* \*\*Load-Balanced Web Search:\*\* Intelligently alternates between Tavily and Brave Search APIs to prevent rate-limiting and ensure high availability.

\* \*\*Secure File Downloads:\*\* Downloads files directly to your workspace with strict MIME-type enforcement and streaming size limits to prevent DoS attacks.

\* \*\*Path Boundary Enforcement:\*\* Cryptographically verifies all file requests to prevent directory traversal attacks outside the designated workspace.



\## 🔑 Prerequisites \& Free Tiers

Syncralis relies on three external services. Each of these providers offers a generous free tier for developers (subject to their respective Terms and Conditions):

\* \*\*Ngrok:\*\* Provides the secure public tunnel for file downloads. Claim your free static domain at \[https://ngrok.com](https://ngrok.com).

\* \*\*Tavily API:\*\* Provides AI-optimized web search results. Get your API key at \[https://tavily.com](https://tavily.com).

\* \*\*Brave Search API:\*\* Provides the fallback web search index. Get your API key at \[https://brave.com/search/api/](https://brave.com/search/api/).



\## 📦 Installation



Install the package globally via your terminal:

\\`\\`\\`bash

npm install -g openclaw-syncralis

\# OR via ClawHub: clawhub package install openclaw-syncralis

\\`\\`\\`



\## ⚙️ Configuration \& Deployment



Syncralis is designed as a hybrid tool. It works perfectly on your native operating system (Windows/Mac/Linux) or securely inside a Dockerized environment. 



Choose the deployment method that matches your OpenClaw setup below.



\### Option 1: Native NPM Setup (Without Docker)

When running OpenClaw natively on your host machine, Syncralis spins up a secure local HTTP server bound strictly to localhost.



1\. Open a new terminal window and run Ngrok to expose the default port:

&#x20;  \\`\\`\\`bash

&#x20;  ngrok http 8080

&#x20;  \\`\\`\\`

2\. Add the generated Ngrok URL to your OpenClaw configuration generally inside (/home/node/.openclaw/openclaw.json):

&#x20;  \\`\\`\\`json

&#x20;  "mcp": {

&#x20;    "servers": {

&#x20;      "syncralis": {

&#x20;        "command": "openclaw-syncralis",

&#x20;        "env": {

&#x20;          "NODE\_ENV": "production",

&#x20;          "FILE\_SERVER\_HOST": "127.0.0.1",

&#x20;          "WORKSPACE\_DIR": "C:/path/to/your/workspace", 

&#x20;          "PUBLIC\_TUNNEL\_URL": "https://your-ngrok-url.ngrok-free.app",

&#x20;          "TAVILY\_API\_KEY": "your\_tavily\_key",

&#x20;          "BRAVE\_API\_KEY": "your\_brave\_key"

&#x20;        }

&#x20;      }

&#x20;    }

&#x20;  }

&#x20;  \\`\\`\\`



\### Option 2: Docker Environment Setup (Recommended for Production)

OpenClaw often executes tools as ephemeral child processes. In a containerized setup, it is highly recommended to run openclaw alongside Ngrok to serve the workspace volume 24/7. This guarantees your download links remain active even after the MCP process shuts down.



1\. Configure your `openclaw.json` generally inside (/home/node/.openclaw/openclaw.json):

&#x20;  \\`\\`\\`json

&#x20;  "mcp": {

&#x20;    "servers": {

&#x20;      "syncralis": {

&#x20;        "command": "openclaw-syncralis",

&#x20;        "env": {

&#x20;          "NODE\_ENV": "production",

&#x20;          "FILE\_SERVER\_HOST": "0.0.0.0",

&#x20;          "WORKSPACE\_DIR": "/shared\_workspace",

&#x20;          "PUBLIC\_TUNNEL\_URL": "https://your-static-domain.ngrok-free.app",

&#x20;          "TAVILY\_API\_KEY": "your\_tavily\_key",

&#x20;          "BRAVE\_API\_KEY": "your\_brave\_key"

&#x20;        }

&#x20;      }

&#x20;    }

&#x20;  }

&#x20;  \\`\\`\\`



2\. ### 🐳 Complete Docker Compose (Just an example only)



If you are running OpenClaw entirely inside Docker, here is a complete, production-ready `docker-compose.yml` template to get Syncralis and Ngrok running together seamlessly. 



\\`\\`\\`yaml

version: '3.8'



networks:

&#x20; mcp\_network:

&#x20;   driver: bridge

services:

&#x20; # Your main OpenClaw instance

&#x20; openclaw\_gateway:

&#x20;   image: openclaw/gateway:latest # Replace with your actual OpenClaw image

&#x20;   container\_name: openclaw\_gateway

&#x20;   restart: unless-stopped

&#x20;   networks:

&#x20;     - mcp\_network

&#x20;   ports:

&#x20;     - "127.0.0.1:18789:18789"

&#x20;   extra\_hosts:

&#x20;     - "host.docker.internal:host-gateway"

&#x20;   volumes:

&#x20;     -  ./claw\_data:/home/node/.openclaw:rw

&#x20;     -  # Your config file

&#x20;     - ./workspace:/shared\_workspace # The directory Syncralis will use

&#x20;   environment:

&#x20;     - WORKSPACE\_DIR=/shared\_workspace

&#x20;     - FILE\_SERVER\_HOST=0.0.0.0

&#x20;     - FILE\_SERVER\_PORT=8080

&#x20;     - PUBLIC\_TUNNEL\_URL=https://<your-custom-domain>.ngrok-free.app

&#x20;     - TAVILY\_API\_KEY=${TAVILY\_API\_KEY}

&#x20;     - BRAVE\_API\_KEY=${BRAVE\_API\_KEY}

&#x20;   deploy:

&#x20;     resources:

&#x20;       limits:

&#x20;         cpus: '2.0' # Hard cap: Cannot exceed 2 CPU cores

&#x20;         memory: 2G

&#x20;       reservations:

&#x20;         memory: 512M

&#x20;   logging:

&#x20;     driver: "json-file"

&#x20;     options:

&#x20;       max-size: "10m"

&#x20;       max-file: "5"

&#x20;       compress: "true"

&#x20;   healthcheck:

&#x20;     test: \["CMD", "curl", "-f", "http://localhost:18789"]

&#x20;     interval: 30s

&#x20;     timeout: 10s

&#x20;     retries: 3

&#x20;     start\_period: 40s



&#x20; # The Ngrok tunnel pointing to Syncralis's internal file server

&#x20; ngrok\_tunnel:

&#x20;   image: ngrok/ngrok:latest

&#x20;   container\_name: ngrok\_tunnel

&#x20;   restart: unless-stopped

&#x20;   networks:

&#x20;     - mcp\_network

&#x20;   command: http openclaw\_gateway:8080 --url=https://<your-custom-domain>.ngrok-free.app --log=stdout

&#x20;   environment:

&#x20;     - NGROK\_AUTHTOKEN=${NGROK\_TOKEN}

&#x20;   depends\_on:

&#x20;     openclaw\_gateway:

&#x20;       condition: service\_healthy

\\`\\`\\`



\## 🛡️ Security Parameters

\* `MAX\_QUERY\_LENGTH`: Defaults to 2000 characters.

\* `REQUEST\_TIMEOUT\_MS`: Defaults to 10000ms (10 seconds) to prevent hung API calls.

\* \*\*Size Limits:\*\* Syncralis enforces a hard limit of `50MB` for all file reads and downloads to prevent memory exhaustion. 



\## 💬 Usage Examples (Prompts)

Once connected, you can ask your OpenClaw agent to perform complex I/O tasks:

\* \*"Search the web for the latest advancements in solid-state batteries."\*

\* \*"Download the PDF from \[URL] and save it as `report.pdf`."\*

\* \*"Generate a mobile download link for `report.pdf`."\*



\---

\*Built for resilient, secure agentic workflows.\*


# Network Sentinel

AI-powered network security monitoring dashboard for Raspberry Pi.

![Dashboard Preview](https://img.shields.io/badge/Status-Active-green) ![Platform](https://img.shields.io/badge/Platform-Raspberry%20Pi-red) ![AI](https://img.shields.io/badge/AI-Llama%203.2-blue)

## Screenshot

![Network Sentinel Dashboard](https://i.ibb.co/FbbgLR8f/Capture-d-e-cran-2026-01-03-a-18-18-54.png)

## Features

- **Network Scanning** - ARP-based device discovery with port scanning
- **AI Analysis** - Local AI security analysis powered by Ollama (Llama 3.2)
- **Risk Assessment** - Automatic risk scoring for each device
- **Discord Alerts** - Real-time notifications for security events
- **PDF Reports** - Generate professional security reports
- **Scheduled Scans** - Automatic scanning via cron
- **Authentication** - JWT-based login system

## Architecture

### System Overview

```mermaid
flowchart TB
    subgraph RPI[Raspberry Pi 5]
        subgraph Frontend[Frontend - Port 3000]
            NEXT[Next.js 16]
            REACT[React 19]
            TW[Tailwind CSS]
        end
        
        subgraph Backend[Backend - Port 8000]
            FAST[FastAPI]
            AUTH[JWT Auth]
            DB[(SQLite)]
        end
        
        subgraph AI[AI Engine - Port 11434]
            OLLAMA[Ollama]
            LLAMA[Llama 3.2]
        end
        
        subgraph Scanner[Network Scanner]
            SCAPY[Scapy]
            ARP[ARP Discovery]
            PORT[Port Scanner]
        end
    end
    
    USER((User)) --> NEXT
    NEXT <--> FAST
    FAST <--> DB
    FAST <--> OLLAMA
    FAST <--> SCAPY
    SCAPY --> ARP
    SCAPY --> PORT
    FAST --> DISCORD[Discord Webhook]
```

### Request Flow

```mermaid
sequenceDiagram
    participant U as User
    participant F as Frontend
    participant B as Backend
    participant S as Scanner
    participant AI as Ollama
    participant D as Discord

    U->>F: Login
    F->>B: POST /api/auth/login
    B-->>F: JWT Token
    
    U->>F: Start Scan
    F->>B: POST /api/scan/start
    B->>S: Execute scan (sudo)
    S-->>B: Device list + ports
    B->>B: Calculate risk scores
    B->>AI: Analyze results
    AI-->>B: Security insights
    B->>D: Send alerts (if any)
    B-->>F: Scan complete
    F-->>U: Display results
```

### Data Model

```mermaid
erDiagram
    SCANS {
        int id PK
        string scan_time
        string network
        int device_count
        json devices
    }
    
    DEVICES {
        string ip PK
        string mac
        string hostname
        string vendor
        json ports
        string risk_level
    }
    
    ALERTS {
        int id PK
        int scan_id FK
        string device_ip
        string alert_type
        string severity
        boolean notified
    }
    
    SETTINGS {
        string key PK
        string value
    }
    
    SCANS ||--o{ DEVICES : contains
    SCANS ||--o{ ALERTS : generates
```

### Component Architecture

```mermaid
graph LR
    subgraph Frontend
        A[page.tsx] --> B[api.ts]
        A --> C[LoginPage]
        A --> D[Dashboard]
    end
    
    subgraph Backend
        E[main.py] --> F[auth.py]
        E --> G[database.py]
        E --> H[discord_notify.py]
        E --> I[pdf_report.py]
    end
    
    subgraph Scanner
        J[network_scanner.py]
    end
    
    B <-->|HTTP/JWT| E
    E <-->|subprocess| J
```

## Tech Stack

**Backend:**
- Python 3.11 + FastAPI
- Scapy (network scanning)
- SQLite (database)
- Ollama (local AI)

**Frontend:**
- Next.js 16
- React 19
- Tailwind CSS (cyberpunk theme)

## Installation

### Prerequisites

- Raspberry Pi 4/5 (or any Linux machine)
- Python 3.11+
- Node.js 20+
- Ollama with Llama 3.2 model

### Setup

1. **Clone the repository**
```bash
git clone https://github.com/e-jaafar/network-sentinel.git
cd network-sentinel
```

2. **Install backend dependencies**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

3. **Install frontend dependencies**
```bash
cd frontend
npm install
npm run build
cd ..
```

4. **Install Ollama and model**
```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2:1b
```

5. **Create data directory**
```bash
mkdir -p data
```

6. **Start the services**
```bash
# Backend
source venv/bin/activate
uvicorn backend.main:app --host 0.0.0.0 --port 8000

# Frontend (in another terminal)
cd frontend
npm run start
```

### Systemd Services (Optional)

Copy the service files for automatic startup:
```bash
sudo cp network-sentinel-backend.service /etc/systemd/system/
sudo cp network-sentinel-frontend.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable network-sentinel-backend network-sentinel-frontend
sudo systemctl start network-sentinel-backend network-sentinel-frontend
```

## Usage

1. Access the dashboard at `http://<your-pi-ip>:3000`
2. Login with default credentials:
   - **Username:** `admin`
   - **Password:** `sentinel`
3. Click "New Scan" to discover devices on your network
4. View AI-powered security analysis

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/login` | POST | Authenticate user |
| `/api/scan/latest` | GET | Get latest scan results |
| `/api/scan/start` | POST | Start new network scan |
| `/api/ai/quick-summary` | GET | Get AI security summary |
| `/api/ai/analyze` | POST | Get detailed AI analysis |
| `/api/report/pdf` | GET | Generate PDF report |
| `/api/settings/discord` | POST | Configure Discord webhook |

## Project Structure

```
network-sentinel/
├── scanner/
│   └── network_scanner.py   # Scapy-based network scanner
├── backend/
│   ├── main.py              # FastAPI application
│   ├── auth.py              # JWT authentication
│   ├── database.py          # SQLite operations
│   ├── discord_notify.py    # Discord webhooks
│   └── pdf_report.py        # PDF generation
├── frontend/
│   ├── src/app/             # Next.js app router
│   └── src/lib/api.ts       # API client
├── data/                    # Scan results & database
├── scheduled_scan.py        # Cron job script
└── *.service                # Systemd service files
```

## Security Notes

- Change the default password after first login
- Network scanning requires root/sudo privileges for ARP packets
- All processing is done locally - no data leaves your network
- The AI model runs entirely on your Raspberry Pi
- All API endpoints (except login) require JWT authentication

## License

MIT License - Feel free to use this for your own projects!

## Author

Made with ❤️ by [e-jaafar](https://github.com/e-jaafar)

# Push Demo

A self-hosted web push notification demo server for testing and training purposes. Built with FastAPI and vanilla JavaScript.

![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)

## Features

- **Web Push Notifications** - Full VAPID-based push notification system
- **Client Management** - Track registered browsers with detailed device info
- **Custom Templates** - Create notification templates with OS-specific icons and themes
- **Scheduled Notifications** - Queue notifications to send at specific times
- **Notification History** - Log of all sent notifications with delivery stats
- **Export Data** - Download client list as CSV or JSON
- **Webhook Support** - HTTP POST on new client registration
- **SSL/TLS Support** - Manual certs or automatic Let's Encrypt via certbot
- **Password Protected** - Admin pages secured with HTTP Basic Auth

## Quick Start

### Prerequisites

- Python 3.8+
- pip

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/push_demo.git
cd push_demo

# Install dependencies
pip install fastapi uvicorn pywebpush cryptography jinja2 python-multipart httpx

# Run the server
python server.py
```

The server will start at `http://localhost:8000`. Login credentials are displayed in the terminal.

### Routes

| Route | Description |
|-------|-------------|
| `/` | Public registration page |
| `/register` | Detailed registration with device info |
| `/dashboard` | Send notifications, view clients |
| `/templates` | Create/manage notification templates |
| `/debug` | Debug tools and subscription info |
| `/admin` | Server configuration |

## Usage

### 1. Register a Browser

Visit `http://localhost:8000/` and click **Register**. Grant notification permission when prompted.

### 2. Send a Notification

Go to `/dashboard`, fill in the notification details, and click **Send push**.

### 3. Create Custom Templates

Visit `/templates` to create reusable notification templates with:
- OS-specific icons (Windows, macOS, Linux, Android, iOS)
- Custom colors and appearance
- Require interaction / silent options

## Configuration

Configuration is stored in `config.json`:

```json
{
  "admin_password": "your-password",
  "ssl_enabled": false,
  "domain": "",
  "webhook_url": "",
  "redirect_url": ""
}
```

### SSL/TLS

**With Let's Encrypt:**
```bash
sudo python server.py --domain push.example.com --email admin@example.com
```

**With manual certificates:**
```bash
python server.py --ssl --ssl-cert /path/to/cert.pem --ssl-key /path/to/key.pem
```

## API Endpoints

### Notifications
- `POST /api/send` - Send notification (form data)
- `POST /api/schedule` - Schedule a notification
- `GET /api/scheduled` - List scheduled notifications
- `GET /api/history` - Get notification history

### Clients
- `GET /api/clients` - List all clients
- `DELETE /api/clients/{id}` - Delete a client
- `GET /api/export/clients?format=json|csv` - Export clients

### Templates
- `GET /api/templates` - List templates
- `POST /api/templates` - Create template
- `PUT /api/templates/{id}` - Update template
- `DELETE /api/templates/{id}` - Delete template

### Admin
- `GET /api/admin/config` - Get configuration
- `POST /api/admin/config` - Update configuration
- `POST /api/admin/password` - Change password

## Project Structure

```
push_demo/
├── server.py           # FastAPI application
├── sw.js               # Service worker for push handling
├── config.json         # Configuration (auto-generated)
├── push_demo.db        # SQLite database (auto-generated)
├── vapid_private.pem   # VAPID private key (auto-generated)
├── vapid_public.pem    # VAPID public key (auto-generated)
└── templates/
    ├── index.html      # Public registration
    ├── register.html   # Detailed registration
    ├── dashboard.html  # Admin dashboard
    ├── templates.html  # Template management
    ├── debug.html      # Debug tools
    └── admin.html      # Server settings
```

## Security Notes

- All push notifications are encrypted in transit (RFC 8291 - ECDH + AES-128-GCM)
- VAPID keys are auto-generated on first run
- Admin password is randomly generated and saved to `config.json`
- The public registration page (`/`) does not require authentication

## License

MIT License - See [LICENSE](LICENSE) for details.

## Acknowledgments

- [pywebpush](https://github.com/web-push-libs/pywebpush) - Web Push library
- [FastAPI](https://fastapi.tiangolo.com/) - Web framework

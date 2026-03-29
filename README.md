# DataBrowse

**One file. Zero dependencies. Full database control.**

DataBrowse is a modern MySQL/MariaDB management platform built as a single PHP file. Upload it to your server, open it in your browser, and start managing your databases.

## Features

- **Single file deployment** — Upload `databrowse.php`, open in browser, done
- **Zero dependencies** — Pure PHP 8.4+, no Composer, no npm, no build step
- **Modern SPA** — Alpine.js + Tailwind CSS, no page reloads
- **SQL Editor** — CodeMirror 6 with syntax highlighting and autocomplete
- **Dark/Light mode** — Follows system preference or manual toggle
- **Full CRUD** — Browse, edit, insert, delete data with inline editing
- **Export/Import** — SQL, CSV, JSON with streaming and progress tracking
- **Security first** — CSP headers, CSRF protection, rate limiting, IP whitelist
- **Mobile ready** — Fully responsive design
- **Schema diff** — Compare two databases and generate ALTER statements
- **User management** — Visual privilege matrix
- **Server monitoring** — Status dashboard, process list, variables

## Quick Start

```bash
# 1. Download
curl -O https://github.com/DataBrowse/DataBrowse/releases/latest/download/databrowse.php

# 2. Upload to your server
scp databrowse.php user@server:/var/www/html/

# 3. Open in browser
# https://yourserver.com/databrowse.php
```

## Requirements

- PHP 8.4+
- ext-mysqli
- ext-mbstring
- ext-session
- MySQL 5.7+ / MariaDB 10.3+

## Configuration (Optional)

Create `databrowse.config.json` in the same directory:

```json
{
  "security": {
    "force_https": true,
    "allow_root_login": false,
    "ip_whitelist": ["10.0.0.0/8"],
    "trusted_proxies": ["127.0.0.1"],
    "allowed_db_hosts": ["127.0.0.1", "localhost"],
    "max_query_limit": 5000
  },
  "ui": {
    "default_theme": "dark",
    "rows_per_page": 50
  }
}
```

## Development

```bash
git clone https://github.com/DataBrowse/DataBrowse.git
cd DataBrowse
composer install
php build.php          # Build databrowse.php
composer test          # Run tests
```

## Comparison

|                    | phpMyAdmin | DataBrowse |
|--------------------|-----------|------------|
| Files              | 3,000+    | 1          |
| Disk usage         | ~60MB     | ~500KB     |
| Dependencies       | 20+ Composer, 100+ npm | 0 |
| Build step         | Webpack + Yarn | None |
| Page transition    | ~500ms    | ~28ms      |
| Memory per request | ~40MB     | ~8MB       |

## License

MIT License - ECOSTACK TECHNOLOGY OÜ

## Links

- Website: [databrowse.dev](https://databrowse.dev)
- GitHub: [github.com/DataBrowse/DataBrowse](https://github.com/DataBrowse/DataBrowse)

# Setup Instructions

## Quick Start

1. **Clone the repository:**
   ```bash
   git clone <your-repo-url>
   cd copilot-agent-testing-demo
   ```

2. **Install dependencies (optional):**
   ```bash
   pip install -r requirements.txt
   ```

   **Note:** The code is designed to work without external dependencies. If `python-ldap` or `pyodbc` are not installed, the corresponding features will be gracefully disabled.

3. **Run the demo:**
   ```bash
   cd after/
   python demo.py
   ```

## What You'll See

The demo will:
- ✅ Process sample data (dict, JSON, XML)
- ✅ Validate emails and phone numbers
- ✅ Save results to `output.json`
- ✅ Simulate backup operations
- ✅ Generate processing reports
- ✅ Show proper logging

## Environment Variables (Optional)

You can customize behavior with environment variables:

```bash
export DB_SERVER="your-server"
export LDAP_SERVER="ldap://your-server:389"
export API_KEY="your-api-key"
# ... see config.py for full list
```

## Dependencies

### Required (Standard Library)
- `json`, `xml.etree.ElementTree`, `re`, `base64`, `datetime`, `os`, `logging`

### Optional
- `python-ldap` - For LDAP authentication (gracefully degrades without it)
- `pyodbc` - For SQL Server connections (gracefully degrades without it)

## Troubleshooting

If you see warnings like:
- `"pyodbc module not available"` - This is expected and normal
- `"LDAP module not available"` - This is expected and normal

The code is designed to work in demo mode without these dependencies.
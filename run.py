#!/usr/bin/env python3
"""
Quick runner script for PhishGuard
Sets up the environment and runs the Flask app
"""

import os
import sys

def main():
    # Set API keys as environment variables for testing
    os.environ['GOOGLE_SAFE_BROWSING_API_KEY'] = 'AIzaSyC9JhAQgRUiMsvHDCl_h1K-3LxjKIkUJ9g'
    os.environ['WHOISXML_API_KEY'] = 'at_yHbGBEeBpmSAT5K5LMAYjUirsqTEh'
    os.environ['VIRUSTOTAL_API_KEY'] = '317c222ce390ea39dea87fc68ab82f45b411e7300bebc941ebb0c9ad3916d49f'
    
    # Import and run the Flask app
    from app import app
    
    print("🛡️  Starting PhishGuard Server...")
    print("📡 Server will be available at: http://localhost:5000")
    print("🔑 API Keys configured and ready")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)

if __name__ == '__main__':
    main()
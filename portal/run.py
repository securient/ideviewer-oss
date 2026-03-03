#!/usr/bin/env python3
"""
Run the IDE Viewer Portal.

Usage:
    python run.py                    # Development mode
    python run.py --production       # Production mode with gunicorn
"""

import os
import sys
import argparse


def main():
    parser = argparse.ArgumentParser(description='Run IDE Viewer Portal')
    parser.add_argument('--production', action='store_true', help='Run in production mode')
    parser.add_argument('--host', default='0.0.0.0', help='Host to bind to')
    parser.add_argument('--port', type=int, default=5000, help='Port to bind to')
    args = parser.parse_args()
    
    if args.production:
        # Use gunicorn for production
        try:
            import gunicorn
        except ImportError:
            print("Error: gunicorn is required for production mode")
            print("Install with: pip install gunicorn")
            sys.exit(1)
        
        os.environ['FLASK_CONFIG'] = 'production'
        os.system(f'gunicorn -w 4 -b {args.host}:{args.port} "app:create_app()"')
    else:
        # Development mode
        os.environ['FLASK_CONFIG'] = 'development'
        
        from app import create_app
        app = create_app('development')
        
        print("\n" + "="*50)
        print("  IDE Viewer Portal - Development Server")
        print("="*50)
        print(f"\n  URL: http://{args.host}:{args.port}")
        print("  Press Ctrl+C to stop\n")
        
        app.run(host=args.host, port=args.port, debug=True)


# Module-level app instance for gunicorn: `gunicorn run:app`
app = None
try:
    from app import create_app
    app = create_app(os.environ.get('FLASK_CONFIG', 'production'))
except Exception:
    pass


if __name__ == '__main__':
    main()

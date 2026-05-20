#!/bin/bash
#
# IDEViewer Portal — Quick Start
#
# Usage:
#   ./start.sh              Local development (SQLite, auto-configured)
#   ./start.sh --docker     Local with Docker + PostgreSQL
#   ./start.sh --aws        Deploy to AWS ECS
#   ./start.sh --help       Show this help
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PORTAL_DIR="$SCRIPT_DIR/portal"
DEPLOY_DIR="$SCRIPT_DIR/deploy"
ENV_FILE="$PORTAL_DIR/.env"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
DIM='\033[2m'
NC='\033[0m'

# ─────────────────────────────────────────────
# Local development
# ─────────────────────────────────────────────
cmd_local() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}  IDEViewer Portal — Local Development${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo ""

    cd "$PORTAL_DIR"

    # Step 1: Python check
    if ! command -v python3 &>/dev/null; then
        echo -e "${RED}Error: python3 is required. Install Python 3.10+${NC}"
        exit 1
    fi

    # Step 2: Virtual environment
    if [ ! -d "venv" ]; then
        echo -e "${CYAN}Creating virtual environment...${NC}"
        python3 -m venv venv
    fi
    source venv/bin/activate

    # Step 3: Install dependencies (if needed)
    if ! python3 -c "import flask" &>/dev/null; then
        echo -e "${CYAN}Installing dependencies...${NC}"
        pip install -q -r requirements.txt
    fi

    # Step 4: Generate .env if missing
    if [ ! -f "$ENV_FILE" ]; then
        echo -e "${CYAN}Generating configuration...${NC}"
        SECRET_KEY=$(python3 -c "import secrets; print(secrets.token_urlsafe(32))")
        cat > "$ENV_FILE" << EOF
# IDEViewer Portal Configuration
# Auto-generated — edit as needed

# Flask secret key (auto-generated, do not share)
SECRET_KEY=$SECRET_KEY

# Database (default: SQLite in portal/instance/)
# For PostgreSQL: DATABASE_URL=postgresql://user:pass@localhost:5432/ideviewer
# DATABASE_URL=

# Google OAuth (optional)
# 1. Go to https://console.cloud.google.com/apis/credentials
# 2. Create a new project (or select existing)
# 3. Go to APIs & Services > Credentials
# 4. Create Credentials > OAuth 2.0 Client ID > Web application
# 5. Add authorized redirect URI: http://localhost:5000/login/google/callback
#    (for production: https://your-domain.com/login/google/callback)
# 6. Copy Client ID and Client Secret below
# GOOGLE_CLIENT_ID=
# GOOGLE_CLIENT_SECRET=

# Local login control
# 'false' = always allow username/password login (default)
# 'auto'  = disable local login when Google OAuth is configured
# 'true'  = always disable local login (requires Google OAuth)
# DISABLE_LOCAL_LOGIN=false

# Portal settings
# PORTAL_URL=http://localhost:5000
EOF
        echo -e "${GREEN}Configuration saved to portal/.env${NC}"
    fi

    # Step 5: Load .env (temporarily disable set -e since .env may have comments/empty lines)
    export FLASK_CONFIG=development
    export FLASK_APP=run.py
    set +e
    set -a
    source "$ENV_FILE" 2>/dev/null
    set +a
    set -e

    # Step 6: Run migrations
    echo -e "${CYAN}Running database migrations...${NC}"
    flask db upgrade 2>&1 | grep -E "Running upgrade|No upgrade" || true

    # Step 7: Start
    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Portal ready!${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo -e "  URL:      ${CYAN}http://localhost:5000${NC}"
    echo -e "  Login:    ${CYAN}admin${NC} / ${CYAN}ideviewer${NC}"
    echo -e "  Config:   ${DIM}portal/.env${NC}"
    echo -e "  Database: ${DIM}portal/instance/ideviewer.db${NC}"
    echo ""
    echo -e "  ${DIM}Press Ctrl+C to stop${NC}"
    echo ""

    flask run --host 0.0.0.0 --port 5000
}

# ─────────────────────────────────────────────
# Docker (local with PostgreSQL)
# ─────────────────────────────────────────────
cmd_docker() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo -e "${CYAN}  IDEViewer Portal — Docker${NC}"
    echo -e "${CYAN}════════════════════════════════════════${NC}"
    echo ""

    if ! command -v docker &>/dev/null; then
        echo -e "${RED}Error: Docker is required. Install from https://docker.com${NC}"
        exit 1
    fi

    cd "$PORTAL_DIR"

    echo -e "${CYAN}Starting services (PostgreSQL + Portal)...${NC}"
    docker-compose up -d --build

    echo ""
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo -e "${GREEN}  Portal ready!${NC}"
    echo -e "${GREEN}════════════════════════════════════════${NC}"
    echo ""
    echo -e "  URL:      ${CYAN}http://localhost:8080${NC}"
    echo -e "  Login:    ${CYAN}admin${NC} / ${CYAN}ideviewer${NC}"
    echo -e "  Database: ${DIM}PostgreSQL (localhost:5432)${NC}"
    echo ""
    echo -e "  Stop:  ${DIM}cd portal && docker-compose down${NC}"
    echo -e "  Logs:  ${DIM}cd portal && docker-compose logs -f portal${NC}"
    echo -e "  Reset: ${DIM}cd portal && docker-compose down -v${NC}"
    echo ""
}

# ─────────────────────────────────────────────
# AWS deployment
# ─────────────────────────────────────────────
cmd_aws() {
    echo ""
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo -e "${CYAN}  IDEViewer Portal — AWS Deployment Wizard${NC}"
    echo -e "${CYAN}════════════════════════════════════════════════${NC}"
    echo ""

    # ── Step 1: Check required tools ──
    echo -e "${CYAN}Step 1: Checking prerequisites${NC}"
    local missing=""
    for cmd in aws terraform docker; do
        if command -v $cmd &>/dev/null; then
            ver=$($cmd --version 2>&1 | head -1)
            echo -e "  ${GREEN}✓${NC} $cmd ($ver)"
        else
            missing="$missing $cmd"
            echo -e "  ${RED}✗${NC} $cmd — not found"
        fi
    done
    if [ -n "$missing" ]; then
        echo ""
        echo -e "${RED}Missing required tools:${missing}${NC}"
        echo ""
        echo "  Install:"
        echo "    aws       → https://aws.amazon.com/cli/"
        echo "    terraform → https://terraform.io/downloads"
        echo "    docker    → https://docker.com"
        exit 1
    fi
    echo ""

    # ── Step 2: Verify AWS credentials ──
    echo -e "${CYAN}Step 2: Verifying AWS credentials${NC}"
    echo ""

    # Check for profile or env vars
    if [ -n "$AWS_PROFILE" ]; then
        echo -e "  Using AWS profile: ${CYAN}$AWS_PROFILE${NC}"
    elif [ -n "$AWS_ACCESS_KEY_ID" ]; then
        MASKED_KEY="${AWS_ACCESS_KEY_ID:0:4}****${AWS_ACCESS_KEY_ID: -4}"
        echo -e "  Using access key: ${CYAN}$MASKED_KEY${NC}"
    else
        echo -e "  Using default credentials (from ~/.aws/credentials or instance role)"
    fi
    echo ""

    if ! aws sts get-caller-identity &>/dev/null; then
        echo -e "${RED}  ✗ AWS credentials are invalid or not configured.${NC}"
        echo ""
        echo "  Options:"
        echo "    1. Run: aws configure"
        echo "    2. Set env vars: export AWS_ACCESS_KEY_ID=... && export AWS_SECRET_ACCESS_KEY=..."
        echo "    3. Set profile: export AWS_PROFILE=your-profile"
        echo ""
        exit 1
    fi

    IDENTITY=$(aws sts get-caller-identity --output json)
    ACCOUNT=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Account'])")
    ARN=$(echo "$IDENTITY" | python3 -c "import sys,json; print(json.load(sys.stdin)['Arn'])")
    REGION=$(aws configure get region 2>/dev/null || echo "us-east-1")

    echo -e "  ${GREEN}✓${NC} Authenticated"
    echo -e "  Account:  ${CYAN}$ACCOUNT${NC}"
    echo -e "  Identity: ${CYAN}$ARN${NC}"
    echo -e "  Region:   ${CYAN}$REGION${NC}"
    echo ""

    echo -e "${YELLOW}  Is this the correct AWS account and region? [y/N]${NC}"
    read -p "  > " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo "  To change region:  export AWS_DEFAULT_REGION=us-west-2"
        echo "  To change account: export AWS_PROFILE=other-profile"
        echo "  Then re-run: ./start.sh --aws"
        exit 0
    fi
    echo ""

    # ── Step 3: Terraform configuration ──
    echo -e "${CYAN}Step 3: Terraform configuration${NC}"
    echo ""

    TFVARS_FILE="$DEPLOY_DIR/terraform/terraform.tfvars"

    if [ ! -f "$TFVARS_FILE" ]; then
        echo -e "  No terraform.tfvars found. Creating from example..."
        cp "$DEPLOY_DIR/terraform/terraform.tfvars.example" "$TFVARS_FILE"
        echo ""
    fi

    echo -e "  ${YELLOW}Please review your configuration:${NC}"
    echo ""
    echo -e "  File: ${CYAN}$TFVARS_FILE${NC}"
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────┐"
    cat "$TFVARS_FILE" | while IFS= read -r line; do
        # Skip empty lines and comments-only lines for display
        if [ -n "$line" ]; then
            echo "  │ $line"
        fi
    done
    echo "  └─────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "  Key settings to verify:"
    echo -e "    ${DIM}• aws_region         — Which region to deploy in${NC}"
    echo -e "    ${DIM}• project_name       — Resource naming prefix (must be unique in your account)${NC}"
    echo -e "    ${DIM}• custom_domain      — Set for HTTPS (requires Route53 hosted zone)${NC}"
    echo -e "    ${DIM}• rds_instance_class  — db.t3.micro (~\$15/mo) or larger${NC}"
    echo -e "    ${DIM}• ecs_min/max_tasks  — Autoscaling range${NC}"
    echo ""

    echo -e "${YELLOW}  Have you reviewed and configured terraform.tfvars? [y/N]${NC}"
    read -p "  > " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo ""
        echo -e "  Edit the file and re-run: ./start.sh --aws"
        echo -e "    ${DIM}nano $TFVARS_FILE${NC}"
        exit 0
    fi
    echo ""

    # ── Step 4: Cost estimate ──
    echo -e "${CYAN}Step 4: Estimated monthly cost${NC}"
    echo ""
    echo "  ┌──────────────────────────┬────────────┐"
    echo "  │ Resource                 │ Est. Cost  │"
    echo "  ├──────────────────────────┼────────────┤"
    echo "  │ ECS Fargate (1 task)     │  ~\$30/mo   │"
    echo "  │ NAT Gateway              │  ~\$32/mo   │"
    echo "  │ RDS PostgreSQL (t3.micro)│  ~\$15/mo   │"
    echo "  │ ALB                      │  ~\$20/mo   │"
    echo "  │ Secrets Manager          │   ~\$2/mo   │"
    echo "  │ CloudWatch + ECR         │   ~\$2/mo   │"
    echo "  ├──────────────────────────┼────────────┤"
    echo "  │ Total                    │ ~\$100/mo   │"
    echo "  └──────────────────────────┴────────────┘"
    echo ""
    echo -e "  ${DIM}Costs vary by region. Destroy with: ./deploy/deploy.sh destroy${NC}"
    echo ""

    # ── Step 5: Final confirmation ──
    echo -e "${YELLOW}  This will create AWS resources in account $ACCOUNT ($REGION).${NC}"
    echo -e "${YELLOW}  Proceed with deployment? [y/N]${NC}"
    read -p "  > " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "  Deployment cancelled."
        exit 0
    fi

    echo ""
    echo -e "${CYAN}Launching deployment...${NC}"
    echo ""
    exec "$DEPLOY_DIR/deploy.sh" init
}

# ─────────────────────────────────────────────
# Help
# ─────────────────────────────────────────────
cmd_help() {
    echo ""
    echo "IDEViewer Portal — Quick Start"
    echo ""
    echo "Usage: ./start.sh [option]"
    echo ""
    echo "Options:"
    echo "  (none)      Start locally (SQLite, auto-configured)"
    echo "  --docker    Start with Docker + PostgreSQL"
    echo "  --aws       Deploy to AWS (ECS Fargate + RDS)"
    echo "  --help      Show this help"
    echo ""
    echo "Local development:"
    echo "  Runs on http://localhost:5000"
    echo "  Uses SQLite (zero config)"
    echo "  Auto-generates SECRET_KEY"
    echo "  Default login: admin / ideviewer"
    echo ""
    echo "Docker:"
    echo "  Runs on http://localhost:8080"
    echo "  Uses PostgreSQL 15"
    echo "  Default login: admin / ideviewer"
    echo ""
    echo "AWS:"
    echo "  ECS Fargate + RDS PostgreSQL + ALB"
    echo "  Secrets auto-generated in AWS Secrets Manager"
    echo "  Optional: custom domain with HTTPS"
    echo "  See deploy/README.md for details"
    echo ""
}

# ─────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────
case "${1:-}" in
    --docker)  cmd_docker ;;
    --aws)     cmd_aws ;;
    --help|-h) cmd_help ;;
    "")        cmd_local ;;
    *)
        echo -e "${RED}Unknown option: $1${NC}"
        cmd_help
        exit 1
        ;;
esac

#!/bin/bash
# IDEViewer Portal - AWS Deployment Script
#
# Usage:
#   ./deploy.sh init      # First-time: terraform init + apply + build + push + deploy
#   ./deploy.sh build     # Build and push Docker image only
#   ./deploy.sh deploy    # Update ECS service with latest image
#   ./deploy.sh destroy   # Tear down all infrastructure
#   ./deploy.sh status    # Show deployment status
#   ./deploy.sh logs      # Tail CloudWatch logs

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TF_DIR="$SCRIPT_DIR/terraform"
PORTAL_DIR="$(dirname "$SCRIPT_DIR")/portal"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Read Terraform outputs
get_tf_output() {
    cd "$TF_DIR"
    terraform output -raw "$1" 2>/dev/null
}

# Check prerequisites
check_prereqs() {
    echo -e "${CYAN}Checking prerequisites...${NC}"
    for cmd in aws terraform docker; do
        if ! command -v $cmd &>/dev/null; then
            echo -e "${RED}Error: $cmd is required but not installed${NC}"
            exit 1
        fi
    done

    # Check AWS credentials
    if ! aws sts get-caller-identity &>/dev/null; then
        echo -e "${RED}Error: AWS credentials not configured. Run 'aws configure' first.${NC}"
        exit 1
    fi
    echo -e "${GREEN}All prerequisites met${NC}"
}

# Initialize and apply Terraform
cmd_init() {
    check_prereqs

    echo -e "${CYAN}Initializing Terraform...${NC}"
    cd "$TF_DIR"
    terraform init

    echo -e "${CYAN}Planning infrastructure...${NC}"
    terraform plan -out=tfplan

    echo ""
    read -p "Apply this plan? [y/N] " -n 1 -r
    echo ""
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Cancelled."
        exit 0
    fi

    echo -e "${CYAN}Applying infrastructure...${NC}"
    terraform apply tfplan
    rm -f tfplan

    echo ""
    echo -e "${GREEN}Infrastructure created!${NC}"
    echo ""

    # Build and deploy
    cmd_build
    cmd_deploy

    echo ""
    echo -e "${GREEN}========================================${NC}"
    echo -e "${GREEN}  Deployment Complete!${NC}"
    echo -e "${GREEN}========================================${NC}"
    echo ""
    echo -e "Portal URL: ${CYAN}$(get_tf_output portal_url)${NC}"
    echo -e "Default login: ${CYAN}admin${NC} / ${CYAN}ideviewer${NC}"
    echo ""
    echo "You will be prompted to change the password on first login."
}

# Build and push Docker image
cmd_build() {
    check_prereqs

    ECR_URL=$(get_tf_output ecr_repository_url)
    REGION=$(get_tf_output aws_region 2>/dev/null || echo "us-east-1")

    if [ -z "$ECR_URL" ]; then
        echo -e "${RED}Error: Could not get ECR URL. Run './deploy.sh init' first.${NC}"
        exit 1
    fi

    echo -e "${CYAN}Logging into ECR...${NC}"
    aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ECR_URL"

    echo -e "${CYAN}Building Docker image...${NC}"
    docker build -t ideviewer-oss-portal "$PORTAL_DIR"

    echo -e "${CYAN}Tagging and pushing to ECR...${NC}"
    docker tag ideviewer-oss-portal:latest "$ECR_URL:latest"
    docker tag ideviewer-oss-portal:latest "$ECR_URL:$(date +%Y%m%d-%H%M%S)"
    docker push "$ECR_URL:latest"
    docker push "$ECR_URL:$(date +%Y%m%d-%H%M%S)"

    echo -e "${GREEN}Image pushed to ECR${NC}"
}

# Update ECS service
cmd_deploy() {
    CLUSTER=$(get_tf_output ecs_cluster_name)
    SERVICE=$(get_tf_output ecs_service_name)

    if [ -z "$CLUSTER" ] || [ -z "$SERVICE" ]; then
        echo -e "${RED}Error: Could not get ECS details. Run './deploy.sh init' first.${NC}"
        exit 1
    fi

    echo -e "${CYAN}Forcing new deployment on ECS...${NC}"
    aws ecs update-service \
        --cluster "$CLUSTER" \
        --service "$SERVICE" \
        --force-new-deployment \
        --query 'service.deployments[0].status' \
        --output text

    echo -e "${CYAN}Waiting for deployment to stabilize...${NC}"
    aws ecs wait services-stable --cluster "$CLUSTER" --services "$SERVICE"

    echo -e "${GREEN}Deployment complete!${NC}"
    echo -e "Portal URL: ${CYAN}$(get_tf_output portal_url)${NC}"
}

# Show status
cmd_status() {
    CLUSTER=$(get_tf_output ecs_cluster_name)
    SERVICE=$(get_tf_output ecs_service_name)

    echo -e "${CYAN}=== IDEViewer Portal Status ===${NC}"
    echo ""
    echo -e "Portal URL:  $(get_tf_output portal_url)"
    echo -e "ALB DNS:     $(get_tf_output alb_dns_name)"
    echo -e "ECR:         $(get_tf_output ecr_repository_url)"
    echo -e "RDS:         $(get_tf_output rds_endpoint)"
    echo ""

    if [ -n "$CLUSTER" ] && [ -n "$SERVICE" ]; then
        echo -e "${CYAN}ECS Service:${NC}"
        aws ecs describe-services \
            --cluster "$CLUSTER" \
            --services "$SERVICE" \
            --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount,Deployments:deployments[*].{Status:status,Running:runningCount,Desired:desiredCount}}' \
            --output table
    fi
}

# Tail logs
cmd_logs() {
    PROJECT=$(cd "$TF_DIR" && terraform output -raw project_name 2>/dev/null || echo "ideviewer")
    LOG_GROUP="/ecs/${PROJECT}-portal"

    echo -e "${CYAN}Tailing CloudWatch logs (Ctrl+C to stop)...${NC}"
    aws logs tail "$LOG_GROUP" --follow --since 5m
}

# Destroy infrastructure
cmd_destroy() {
    echo -e "${YELLOW}WARNING: This will destroy ALL infrastructure including the database!${NC}"
    read -p "Are you sure? Type 'destroy' to confirm: " confirm
    if [ "$confirm" != "destroy" ]; then
        echo "Cancelled."
        exit 0
    fi

    cd "$TF_DIR"
    terraform destroy
}

# Main
case "${1:-help}" in
    init)    cmd_init ;;
    build)   cmd_build ;;
    deploy)  cmd_deploy ;;
    status)  cmd_status ;;
    logs)    cmd_logs ;;
    destroy) cmd_destroy ;;
    *)
        echo "IDEViewer Portal - AWS Deployment"
        echo ""
        echo "Usage: ./deploy.sh <command>"
        echo ""
        echo "Commands:"
        echo "  init      First-time setup: create infrastructure + build + deploy"
        echo "  build     Build and push Docker image to ECR"
        echo "  deploy    Update ECS service with latest image"
        echo "  status    Show deployment status"
        echo "  logs      Tail CloudWatch logs"
        echo "  destroy   Tear down all infrastructure"
        ;;
esac

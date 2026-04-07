---
title: AWS (ECS + RDS)
nav_order: 3
parent: Deployment
---

# AWS Deployment

Deploy the IDEViewer portal to AWS using ECS Fargate, RDS PostgreSQL, and Application Load Balancer via Terraform.

## Architecture

```
Internet
    |
    v
[Application Load Balancer]  <- HTTPS (custom domain) or HTTP (ALB DNS)
    |
    v
[ECS Fargate Service]        <- 1-4 tasks, auto-scaling on CPU
    |           |
    v           v
[RDS PostgreSQL]   [AWS Secrets Manager]
 (private)          SECRET_KEY
                    DATABASE_URL
                    Google OAuth (optional)
```

## Prerequisites

- [AWS CLI v2](https://aws.amazon.com/cli/) configured with appropriate credentials
- [Terraform >= 1.5](https://www.terraform.io/downloads)
- [Docker](https://www.docker.com/products/docker-desktop/)
- An AWS account with permissions for: ECS, ECR, RDS, ALB, VPC, Secrets Manager, CloudWatch, IAM

## Quick Start

### 1. Configure

```bash
cd deploy/terraform
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your preferences
```

### 2. Deploy

```bash
./start.sh --aws
```

The wizard verifies AWS credentials, reviews your Terraform configuration, shows cost estimates, and confirms before creating resources. Alternatively:

```bash
cd deploy
./deploy.sh init
```

### 3. Access

The deployment script prints the portal URL. Default credentials:

| Username | Password |
|----------|----------|
| `admin` | `ideviewer` |

## Terraform Variables

### Required

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region | `us-east-1` |
| `project_name` | Resource name prefix (must be unique in your account) | `ideviewer` |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `custom_domain` | Custom domain (e.g., `portal.example.com`) | `""` (uses ALB DNS) |
| `route53_zone_id` | Route53 zone ID for custom domain | `""` |
| `google_client_id` | Google OAuth Client ID | `""` |
| `google_client_secret` | Google OAuth Client Secret | `""` |
| `ecs_cpu` | ECS task CPU (1024 = 1 vCPU) | `1024` |
| `ecs_memory` | ECS task memory (MB) | `2048` |
| `ecs_min_tasks` | Minimum ECS tasks | `1` |
| `ecs_max_tasks` | Maximum ECS tasks | `4` |
| `rds_instance_class` | RDS instance type | `db.t3.micro` |
| `free_tier_host_limit` | Max hosts per customer key | `5` |

## Custom Domain Setup

1. Create a Route53 hosted zone for your domain
2. Set the variables in `terraform.tfvars`:

```hcl
custom_domain   = "portal.securient.com"
route53_zone_id = "Z1234567890ABC"
```

3. Run `./deploy.sh init` -- Terraform creates the ACM certificate and DNS records automatically

## Cost Estimates

Approximate monthly costs (us-east-1, minimal configuration):

| Resource | Spec | Est. Cost |
|----------|------|-----------|
| ECS Fargate | 1 task, 1 vCPU, 2GB | ~$30/mo |
| NAT Gateway | 1 gateway | ~$32/mo |
| RDS PostgreSQL | db.t3.micro, 20GB | ~$15/mo |
| ALB | 1 ALB + LCUs | ~$20/mo |
| Secrets Manager | 4 secrets | ~$2/mo |
| CloudWatch + ECR | Logs + image storage | ~$2/mo |
| **Total** | | **~$100/mo** |

To reduce costs:
- Use `db.t3.micro` with single-AZ (already default)
- Replace NAT Gateway with a NAT instance (~$4/mo)
- Use reserved pricing for Fargate and RDS for long-term savings

## Operations

```bash
# Update portal (after code changes)
./deploy.sh build    # Build + push new Docker image
./deploy.sh deploy   # Rolling update on ECS

# View logs
./deploy.sh logs     # Tail CloudWatch logs

# Check status
./deploy.sh status   # ECS service status, URLs, endpoints

# Scale manually
aws ecs update-service \
  --cluster ideviewer-cluster \
  --service ideviewer-oss-portal \
  --desired-count 3
```

## Connect Daemons

After deployment, register daemons using the portal URL:

```bash
ideviewer register \
  --customer-key YOUR-KEY \
  --portal-url https://portal.securient.com
```

## Tear Down

```bash
./deploy.sh destroy
```

{: .warning }
This removes ALL resources including the database. Export any data before destroying.

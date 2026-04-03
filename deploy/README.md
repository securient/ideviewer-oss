# IDEViewer Portal - AWS Deployment

Deploy the IDEViewer portal to AWS using ECS Fargate, RDS PostgreSQL, and Application Load Balancer.

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
cd deploy
./deploy.sh init
```

This will:
1. Create all AWS infrastructure (VPC, ECS, RDS, ALB, etc.)
2. Build the Docker image
3. Push to ECR
4. Deploy to ECS

### 3. Access

The deployment script will print the portal URL. Default credentials:

```
Username: admin
Password: ideviewer
```

You'll be prompted to change the password on first login.

## Configuration

### Required Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `aws_region` | AWS region | `us-east-1` |
| `project_name` | Resource name prefix | `ideviewer` |

### Optional Variables

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

### Custom Domain Setup

1. Create a Route53 hosted zone for your domain
2. Set the variables:
   ```hcl
   custom_domain   = "portal.securient.com"
   route53_zone_id = "Z1234567890ABC"
   ```
3. Run `./deploy.sh init` -- Terraform will create the ACM certificate and DNS records automatically

### Google OAuth Setup

To enable "Sign in with Google":

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new project (or select existing)
3. Go to **APIs & Services > Credentials**
4. Click **Create Credentials > OAuth 2.0 Client ID**
5. Choose **Web application**
6. Set **Authorized redirect URIs** to:
   - `https://your-portal-domain.com/login/google/callback`
   - Or `http://your-alb-dns.amazonaws.com/login/google/callback` (for testing)
7. Copy the Client ID and Client Secret
8. Add to `terraform.tfvars`:
   ```hcl
   google_client_id     = "123456789-abc.apps.googleusercontent.com"
   google_client_secret = "GOCSPX-your-secret"
   ```
9. Run `./deploy.sh deploy` to update

## Operations

### Update the portal

After code changes:

```bash
./deploy.sh build    # Build + push new image
./deploy.sh deploy   # Rolling update on ECS
```

### View logs

```bash
./deploy.sh logs     # Tail CloudWatch logs
```

### Check status

```bash
./deploy.sh status   # ECS service status, URLs, endpoints
```

### Scale manually

```bash
aws ecs update-service \
  --cluster ideviewer-cluster \
  --service ideviewer-portal \
  --desired-count 3
```

### Connect daemon to the portal

After deployment, register daemons using the portal URL:

```bash
ideviewer register \
  --customer-key YOUR-KEY \
  --portal-url https://portal.securient.com  # or your ALB DNS
```

## Cost Estimate

Approximate monthly costs (us-east-1, minimal config):

| Resource | Spec | Est. Cost |
|----------|------|-----------|
| ECS Fargate | 1 task, 1 vCPU, 2GB | ~$30 |
| RDS PostgreSQL | db.t3.micro, 20GB | ~$15 |
| ALB | 1 ALB + LCUs | ~$20 |
| NAT Gateway | 1 gateway | ~$32 |
| Secrets Manager | 4 secrets | ~$2 |
| CloudWatch | Logs | ~$1 |
| ECR | Image storage | ~$1 |
| **Total** | | **~$100/month** |

To reduce costs:
- Use `db.t3.micro` with single-AZ (already default)
- Consider replacing NAT Gateway with a NAT instance (~$4/month)
- Use reserved pricing for Fargate and RDS for long-term savings

## Tear Down

```bash
./deploy.sh destroy
```

This removes ALL resources including the database. Make sure to export any data first.

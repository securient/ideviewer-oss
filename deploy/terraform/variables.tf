variable "aws_region" {
  description = "AWS region for all resources"
  type        = string
  default     = "us-east-1"
}

variable "project_name" {
  description = "Project name used for resource naming and tagging"
  type        = string
  default     = "ideviewer"
}

variable "environment" {
  description = "Deployment environment (e.g., production, staging)"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "ecs_cpu" {
  description = "CPU units for ECS task (1024 = 1 vCPU)"
  type        = number
  default     = 1024
}

variable "ecs_memory" {
  description = "Memory (MiB) for ECS task"
  type        = number
  default     = 2048
}

variable "ecs_min_tasks" {
  description = "Minimum number of ECS tasks"
  type        = number
  default     = 1
}

variable "ecs_max_tasks" {
  description = "Maximum number of ECS tasks"
  type        = number
  default     = 4
}

variable "rds_instance_class" {
  description = "RDS instance class"
  type        = string
  default     = "db.t3.micro"
}

variable "rds_allocated_storage" {
  description = "Initial allocated storage in GB"
  type        = number
  default     = 20
}

variable "rds_max_allocated_storage" {
  description = "Maximum allocated storage in GB (autoscaling)"
  type        = number
  default     = 100
}

variable "container_port" {
  description = "Port the container listens on"
  type        = number
  default     = 8080
}

variable "custom_domain" {
  description = "Custom domain for the portal (e.g., portal.securient.com). Leave empty to use ALB DNS."
  type        = string
  default     = ""
}

variable "route53_zone_id" {
  description = "Route53 hosted zone ID for custom domain. Required if custom_domain is set."
  type        = string
  default     = ""
}

variable "google_client_id" {
  description = "Google OAuth Client ID (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "google_client_secret" {
  description = "Google OAuth Client Secret (optional)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "free_tier_host_limit" {
  description = "Maximum hosts per customer key (0 = unlimited)"
  type        = number
  default     = 5
}

variable "disable_local_login" {
  description = "Disable local username/password login. 'false' = always allow, 'auto' = disable when Google OAuth is configured, 'true' = always disable"
  type        = string
  default     = "auto"
}

variable "rds_skip_final_snapshot" {
  description = "Skip final snapshot when destroying RDS instance"
  type        = bool
  default     = true
}

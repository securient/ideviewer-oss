output "portal_url" {
  description = "URL to access the portal"
  value       = var.custom_domain != "" ? "https://${var.custom_domain}" : "http://${aws_lb.main.dns_name}"
}

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.main.dns_name
}

output "ecr_repository_url" {
  description = "ECR repository URL for pushing container images"
  value       = aws_ecr_repository.portal.repository_url
}

output "rds_endpoint" {
  description = "RDS instance endpoint"
  value       = aws_db_instance.main.endpoint
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = aws_ecs_cluster.main.name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = aws_ecs_service.portal.name
}

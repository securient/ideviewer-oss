# -----------------------------------------------------------------------------
# CloudWatch Log Group
# -----------------------------------------------------------------------------

resource "aws_cloudwatch_log_group" "portal" {
  name              = "/ecs/${local.name_prefix}-portal"
  retention_in_days = 30

  tags = {
    Name = "${local.name_prefix}-portal-logs"
  }
}

# -----------------------------------------------------------------------------
# ECS Cluster
# -----------------------------------------------------------------------------

resource "aws_ecs_cluster" "main" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }

  tags = {
    Name = "${local.name_prefix}-cluster"
  }
}

# -----------------------------------------------------------------------------
# IAM - Task Execution Role (pulls images, reads secrets)
# -----------------------------------------------------------------------------

data "aws_iam_policy_document" "ecs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name_prefix}-ecs-execution"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json

  tags = {
    Name = "${local.name_prefix}-ecs-execution"
  }
}

resource "aws_iam_role_policy_attachment" "ecs_execution_base" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

data "aws_iam_policy_document" "ecs_execution_secrets" {
  statement {
    actions = [
      "secretsmanager:GetSecretValue",
    ]
    resources = [
      aws_secretsmanager_secret.app_config.arn,
    ]
  }
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name   = "${local.name_prefix}-ecs-secrets"
  role   = aws_iam_role.ecs_execution.id
  policy = data.aws_iam_policy_document.ecs_execution_secrets.json
}

# -----------------------------------------------------------------------------
# IAM - Task Role (runtime permissions for the container)
# -----------------------------------------------------------------------------

resource "aws_iam_role" "ecs_task" {
  name               = "${local.name_prefix}-ecs-task"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json

  tags = {
    Name = "${local.name_prefix}-ecs-task"
  }
}

# -----------------------------------------------------------------------------
# ECS Task Definition
# -----------------------------------------------------------------------------

locals {
  portal_url = var.custom_domain != "" ? "https://${var.custom_domain}" : "http://${aws_lb.main.dns_name}"
}

resource "aws_ecs_task_definition" "portal" {
  family                   = "${local.name_prefix}-portal"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.ecs_cpu
  memory                   = var.ecs_memory
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  container_definitions = jsonencode([
    {
      name      = "portal"
      image     = "${aws_ecr_repository.portal.repository_url}:latest"
      essential = true

      portMappings = [
        {
          containerPort = var.container_port
          hostPort      = var.container_port
          protocol      = "tcp"
        }
      ]

      environment = [
        { name = "FLASK_CONFIG", value = "production" },
        { name = "PORTAL_URL", value = local.portal_url },
        { name = "FREE_TIER_HOST_LIMIT", value = tostring(var.free_tier_host_limit) },
      ]

      secrets = [
        {
          name      = "SECRET_KEY"
          valueFrom = "${aws_secretsmanager_secret.app_config.arn}:SECRET_KEY::"
        },
        {
          name      = "DATABASE_URL"
          valueFrom = "${aws_secretsmanager_secret.app_config.arn}:DATABASE_URL::"
        },
        {
          name      = "GOOGLE_CLIENT_ID"
          valueFrom = "${aws_secretsmanager_secret.app_config.arn}:GOOGLE_CLIENT_ID::"
        },
        {
          name      = "GOOGLE_CLIENT_SECRET"
          valueFrom = "${aws_secretsmanager_secret.app_config.arn}:GOOGLE_CLIENT_SECRET::"
        },
      ]

      logConfiguration = {
        logDriver = "awslogs"
        options = {
          "awslogs-group"         = aws_cloudwatch_log_group.portal.name
          "awslogs-region"        = var.aws_region
          "awslogs-stream-prefix" = "portal"
        }
      }
    }
  ])

  tags = {
    Name = "${local.name_prefix}-portal"
  }
}

# -----------------------------------------------------------------------------
# ECS Service
# -----------------------------------------------------------------------------

resource "aws_ecs_service" "portal" {
  name            = "${local.name_prefix}-portal"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.portal.arn
  desired_count   = var.ecs_min_tasks
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = aws_subnet.private[*].id
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.portal.arn
    container_name   = "portal"
    container_port   = var.container_port
  }

  depends_on = [
    aws_lb_listener.http,
    aws_db_instance.main,
    aws_secretsmanager_secret_version.app_config,
  ]

  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = {
    Name = "${local.name_prefix}-portal"
  }
}

# -----------------------------------------------------------------------------
# Auto Scaling
# -----------------------------------------------------------------------------

resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = var.ecs_max_tasks
  min_capacity       = var.ecs_min_tasks
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.portal.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "ecs_cpu" {
  name               = "${local.name_prefix}-cpu-autoscaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

# -----------------------------------------------------------------------------
# Application Load Balancer
# -----------------------------------------------------------------------------

resource "aws_lb" "main" {
  name               = "${local.name_prefix}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id

  tags = {
    Name = "${local.name_prefix}-alb"
  }
}

# -----------------------------------------------------------------------------
# Target Group
# -----------------------------------------------------------------------------

resource "aws_lb_target_group" "portal" {
  name        = "${local.name_prefix}-portal-tg"
  port        = var.container_port
  protocol    = "HTTP"
  vpc_id      = aws_vpc.main.id
  target_type = "ip"

  health_check {
    enabled             = true
    path                = "/api/health"
    port                = "traffic-port"
    protocol            = "HTTP"
    healthy_threshold   = 3
    unhealthy_threshold = 3
    timeout             = 5
    interval            = 30
    matcher             = "200"
  }

  tags = {
    Name = "${local.name_prefix}-portal-tg"
  }
}

# -----------------------------------------------------------------------------
# HTTP Listener (always created)
# - With custom domain: redirects to HTTPS
# - Without custom domain: forwards to target group
# -----------------------------------------------------------------------------

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.custom_domain != "" ? "redirect" : "forward"

    # Forward action (used when no custom domain)
    dynamic "forward" {
      for_each = var.custom_domain == "" ? [] : []
      content {
        target_group {
          arn = aws_lb_target_group.portal.arn
        }
      }
    }

    # Redirect action (used when custom domain is set)
    dynamic "redirect" {
      for_each = var.custom_domain != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    # When no custom domain, forward directly
    target_group_arn = var.custom_domain == "" ? aws_lb_target_group.portal.arn : null
  }
}

# -----------------------------------------------------------------------------
# ACM Certificate (only with custom domain)
# -----------------------------------------------------------------------------

resource "aws_acm_certificate" "main" {
  count = var.custom_domain != "" ? 1 : 0

  domain_name       = var.custom_domain
  validation_method = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name = "${local.name_prefix}-cert"
  }
}

resource "aws_route53_record" "cert_validation" {
  for_each = var.custom_domain != "" ? {
    for dvo in aws_acm_certificate.main[0].domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  } : {}

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = var.route53_zone_id
}

resource "aws_acm_certificate_validation" "main" {
  count = var.custom_domain != "" ? 1 : 0

  certificate_arn         = aws_acm_certificate.main[0].arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# -----------------------------------------------------------------------------
# HTTPS Listener (only with custom domain)
# NOTE: HTTPS requires a custom domain with a valid ACM certificate.
#       ALB does not support HTTPS with its default *.amazonaws.com DNS name.
# -----------------------------------------------------------------------------

resource "aws_lb_listener" "https" {
  count = var.custom_domain != "" ? 1 : 0

  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = aws_acm_certificate_validation.main[0].certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.portal.arn
  }
}

# -----------------------------------------------------------------------------
# Route53 Alias Record (only with custom domain)
# -----------------------------------------------------------------------------

resource "aws_route53_record" "portal" {
  count = var.custom_domain != "" ? 1 : 0

  zone_id = var.route53_zone_id
  name    = var.custom_domain
  type    = "A"

  alias {
    name                   = aws_lb.main.dns_name
    zone_id                = aws_lb.main.zone_id
    evaluate_target_health = true
  }
}

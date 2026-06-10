# -----------------------------------------------------------------------------
# ElastiCache Redis for the portal job queue (RQ).
# -----------------------------------------------------------------------------

resource "aws_security_group" "redis" {
  name        = "${local.name_prefix}-redis-sg"
  description = "Allow Redis from ECS only"
  vpc_id      = aws_vpc.main.id

  tags = {
    Name = "${local.name_prefix}-redis-sg"
  }
}

resource "aws_vpc_security_group_ingress_rule" "redis_from_ecs" {
  security_group_id            = aws_security_group.redis.id
  description                  = "Redis from ECS"
  from_port                    = 6379
  to_port                      = 6379
  ip_protocol                  = "tcp"
  referenced_security_group_id = aws_security_group.ecs.id
}

# -----------------------------------------------------------------------------
# Subnet group
# -----------------------------------------------------------------------------

resource "aws_elasticache_subnet_group" "redis" {
  name       = "${local.name_prefix}-redis"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-redis-subnet-group"
  }
}

# -----------------------------------------------------------------------------
# Parameter group
# -----------------------------------------------------------------------------

resource "aws_elasticache_parameter_group" "redis" {
  family = "redis7"
  name   = "${local.name_prefix}-redis7"

  parameter {
    name  = "maxmemory-policy"
    value = "allkeys-lru"
  }

  tags = {
    Name = "${local.name_prefix}-redis7"
  }
}

# -----------------------------------------------------------------------------
# Cluster
# -----------------------------------------------------------------------------

resource "random_password" "redis_auth" {
  length  = 32
  special = false # ElastiCache AUTH tokens must be alphanumeric-safe
}

# A single-node replication group (cluster mode disabled). We use this rather
# than aws_elasticache_cluster because AUTH tokens and at-rest encryption are
# only available on replication groups. The job queue carries host/finding
# identifiers, so it must not be an unauthenticated plaintext service on the
# VPC network.
resource "aws_elasticache_replication_group" "main" {
  replication_group_id = "${local.name_prefix}-redis"
  description          = "IDEViewer portal job queue (RQ)"
  engine               = "redis"
  engine_version       = "7.1"
  node_type            = var.redis_node_type
  num_cache_clusters   = 1
  parameter_group_name = aws_elasticache_parameter_group.redis.name
  subnet_group_name    = aws_elasticache_subnet_group.redis.name
  security_group_ids   = [aws_security_group.redis.id]
  port                 = 6379

  automatic_failover_enabled = false

  transit_encryption_enabled = true
  at_rest_encryption_enabled = true
  auth_token                 = random_password.redis_auth.result

  tags = {
    Name = "${local.name_prefix}-redis"
  }
}

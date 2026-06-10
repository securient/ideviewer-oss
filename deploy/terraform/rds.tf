# -----------------------------------------------------------------------------
# RDS PostgreSQL
# -----------------------------------------------------------------------------

locals {
  rds_username = "ideviewer_admin"
}

resource "aws_db_subnet_group" "main" {
  name       = "${local.name_prefix}-db-subnet"
  subnet_ids = aws_subnet.private[*].id

  tags = {
    Name = "${local.name_prefix}-db-subnet"
  }
}

resource "aws_db_instance" "main" {
  identifier = "${local.name_prefix}-postgres"

  engine         = "postgres"
  engine_version = "15"
  instance_class = var.rds_instance_class

  allocated_storage     = var.rds_allocated_storage
  max_allocated_storage = var.rds_max_allocated_storage
  storage_type          = "gp3"

  # Encryption at rest. The portal DB holds every host's findings, secret
  # locations and CVEs — it must be encrypted. Uses the AWS-managed RDS KMS
  # key unless rds_kms_key_id is supplied.
  storage_encrypted = true
  kms_key_id        = var.rds_kms_key_id != "" ? var.rds_kms_key_id : null

  db_name  = "ideviewer"
  username = local.rds_username
  password = random_password.rds_master_password.result

  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.rds.id]
  publicly_accessible    = false

  backup_retention_period = 7
  backup_window           = "03:00-04:00"
  maintenance_window      = "sun:04:00-sun:05:00"

  skip_final_snapshot       = var.rds_skip_final_snapshot
  final_snapshot_identifier = var.rds_skip_final_snapshot ? null : "${local.name_prefix}-final-snapshot"

  apply_immediately   = true
  deletion_protection = var.rds_deletion_protection

  tags = {
    Name = "${local.name_prefix}-postgres"
  }
}

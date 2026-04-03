# -----------------------------------------------------------------------------
# Random Passwords
# -----------------------------------------------------------------------------

resource "random_password" "secret_key" {
  length  = 32
  special = true
}

resource "random_password" "rds_master_password" {
  length           = 32
  special          = true
  override_special = "!#$%^&*()-_=+[]{}|:,.<>?"
}

# -----------------------------------------------------------------------------
# Secrets Manager - App Configuration
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "app_config" {
  name                    = "${local.name_prefix}/app-config"
  description             = "IDEViewer portal application configuration"
  recovery_window_in_days = 7

  tags = {
    Name = "${local.name_prefix}-app-config"
  }
}

resource "aws_secretsmanager_secret_version" "app_config" {
  secret_id = aws_secretsmanager_secret.app_config.id

  secret_string = jsonencode({
    SECRET_KEY           = base64encode(random_password.secret_key.result)
    DATABASE_URL         = "postgresql://${local.rds_username}:${random_password.rds_master_password.result}@${aws_db_instance.main.endpoint}/ideviewer"
    GOOGLE_CLIENT_ID     = var.google_client_id
    GOOGLE_CLIENT_SECRET = var.google_client_secret
  })

  depends_on = [aws_db_instance.main]
}

# -----------------------------------------------------------------------------
# Secrets Manager - RDS Credentials (standalone for rotation support)
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "rds_credentials" {
  name                    = "${local.name_prefix}/rds-credentials"
  description             = "RDS master credentials for IDEViewer"
  recovery_window_in_days = 7

  tags = {
    Name = "${local.name_prefix}-rds-credentials"
  }
}

resource "aws_secretsmanager_secret_version" "rds_credentials" {
  secret_id = aws_secretsmanager_secret.rds_credentials.id

  secret_string = jsonencode({
    username = local.rds_username
    password = random_password.rds_master_password.result
    host     = aws_db_instance.main.address
    port     = 5432
    dbname   = "ideviewer"
  })

  depends_on = [aws_db_instance.main]
}

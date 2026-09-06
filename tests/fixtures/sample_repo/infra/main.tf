# IaC targets: Checkov flags the open security group (CKV_AWS_24/23) and the RDS instance
# (public, unencrypted, no backups, hard-coded password).
resource "aws_security_group" "open_ssh" {
  name        = "open-ssh"
  description = "SSH open to the world"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "db" {
  allocated_storage   = 10
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  username            = "admin"
  password            = "changeme123"
  publicly_accessible = true
  skip_final_snapshot = true
}

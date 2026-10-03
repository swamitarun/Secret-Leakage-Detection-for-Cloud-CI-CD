# Critical Leak: Hardcoded synthetic AWS credentials inside a production Terraform IAM Role & Instance
provider "aws" {
  region = "us-east-1"
}

resource "aws_instance" "web_server" {
  ami           = "ami-0c55b159cbfafe1f0"
  instance_type = "t3.micro"
  
  # Dangerous hardcoded credential
  access_key = "AKIA1234567890FAKEEX"
  
  tags = {
    Name        = "web-server"
    Environment = "production"
  }
}

resource "aws_iam_role" "app_exec" {
  name = "app_execution_role"
  # Sensitive resource context
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ec2.amazonaws.com" }
    }]
  })
}

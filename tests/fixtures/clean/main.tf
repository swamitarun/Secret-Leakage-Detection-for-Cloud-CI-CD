provider "aws" {
  region = "us-east-1"
}

resource "aws_s3_bucket" "app_storage" {
  bucket = "my-secure-prod-bucket-10293"
  tags = {
    Environment = "production"
    ManagedBy   = "Terraform"
  }
}

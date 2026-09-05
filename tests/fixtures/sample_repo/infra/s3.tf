# IaC target: public bucket without encryption or versioning
resource "aws_s3_bucket" "logs" {
  bucket = "sample-public-logs"
  acl    = "public-read"
}

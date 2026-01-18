# KSI-IAM: Identity and Access Management Controls - AWS

control "ksi_iam_01_aws" {
  title       = "KSI-IAM-01: Unique User Accounts"
  description = "Ensure every real person has a unique account"
  severity    = "high"

  query = query.ksi_iam_01_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-IAM-01"
  })
}

control "ksi_iam_02_aws" {
  title       = "KSI-IAM-02: MFA Enforcement"
  description = "Ensure MFA is enabled for users with console access"
  severity    = "critical"

  query = query.ksi_iam_02_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-IAM-02"
  })
}

control "ksi_iam_03_aws" {
  title       = "KSI-IAM-03: Access Key Rotation"
  description = "Ensure access keys are rotated within required timeframes"
  severity    = "medium"

  query = query.ksi_iam_03_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-IAM-03"
  })
}

control "ksi_iam_04_aws" {
  title       = "KSI-IAM-04: Privileged Access Restrictions"
  description = "Ensure privileged access is restricted and monitored"
  severity    = "high"

  query = query.ksi_iam_04_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-IAM-04"
  })
}

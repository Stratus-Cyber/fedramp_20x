# KSI-MLA: Monitoring, Logging, Auditing Controls - AWS

control "ksi_mla_01_aws" {
  title       = "KSI-MLA-01: Audit Logging Enabled"
  description = "Ensure CloudTrail is enabled for audit logging"
  severity    = "critical"

  query = query.ksi_mla_01_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-MLA-01"
  })
}

control "ksi_mla_02_aws" {
  title       = "KSI-MLA-02: Log Encryption"
  description = "Ensure audit logs are encrypted"
  severity    = "high"

  query = query.ksi_mla_02_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-MLA-02"
  })
}

control "ksi_mla_03_aws" {
  title       = "KSI-MLA-03: Log Integrity Validation"
  description = "Ensure log file integrity validation is enabled"
  severity    = "high"

  query = query.ksi_mla_03_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-MLA-03"
  })
}

control "ksi_mla_04_aws" {
  title       = "KSI-MLA-04: Security Monitoring"
  description = "Ensure security monitoring services are enabled"
  severity    = "high"

  query = query.ksi_mla_04_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-MLA-04"
  })
}

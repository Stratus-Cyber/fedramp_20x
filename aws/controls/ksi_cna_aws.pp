# KSI-CNA: Cloud Native Architecture Controls - AWS

control "ksi_cna_01_aws" {
  title       = "KSI-CNA-01: Encryption at Rest"
  description = "Ensure data at rest is encrypted"
  severity    = "high"

  query = query.ksi_cna_01_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-CNA-01"
  })
}

control "ksi_cna_02_aws" {
  title       = "KSI-CNA-02: Encryption in Transit"
  description = "Ensure data in transit is encrypted"
  severity    = "high"

  query = query.ksi_cna_02_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-CNA-02"
  })
}

control "ksi_cna_03_aws" {
  title       = "KSI-CNA-03: Network Segmentation"
  description = "Ensure proper network segmentation and access controls"
  severity    = "high"

  query = query.ksi_cna_03_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-CNA-03"
  })
}

control "ksi_cna_04_aws" {
  title       = "KSI-CNA-04: Public Access Restrictions"
  description = "Ensure resources are not publicly accessible unless required"
  severity    = "critical"

  query = query.ksi_cna_04_aws_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_id         = "KSI-CNA-04"
  })
}

# KSI-IAM: Identity and Access Management Controls - Azure

control "ksi_iam_01_azure" {
  title       = "KSI-IAM-01: Unique User Accounts"
  description = "Ensure every real person has a unique account"
  severity    = "high"

  query = query.ksi_iam_01_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-IAM-01"
  })
}

control "ksi_iam_02_azure" {
  title       = "KSI-IAM-02: MFA Enforcement"
  description = "Ensure MFA is enabled for users"
  severity    = "critical"

  query = query.ksi_iam_02_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-IAM-02"
  })
}

control "ksi_iam_03_azure" {
  title       = "KSI-IAM-03: Guest User Restrictions"
  description = "Ensure guest user access is restricted"
  severity    = "medium"

  query = query.ksi_iam_03_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-IAM-03"
  })
}

control "ksi_iam_04_azure" {
  title       = "KSI-IAM-04: Privileged Access Restrictions"
  description = "Ensure privileged access is restricted and monitored"
  severity    = "high"

  query = query.ksi_iam_04_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-IAM-04"
  })
}

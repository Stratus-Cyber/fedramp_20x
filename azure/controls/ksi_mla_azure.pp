# KSI-MLA: Monitoring, Logging, Auditing Controls - Azure

control "ksi_mla_01_azure" {
  title       = "KSI-MLA-01: Audit Logging Enabled"
  description = "Ensure Activity Log is configured for audit logging"
  severity    = "critical"

  query = query.ksi_mla_01_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-MLA-01"
  })
}

control "ksi_mla_02_azure" {
  title       = "KSI-MLA-02: Log Retention"
  description = "Ensure audit logs have adequate retention"
  severity    = "high"

  query = query.ksi_mla_02_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-MLA-02"
  })
}

control "ksi_mla_03_azure" {
  title       = "KSI-MLA-03: Diagnostic Settings"
  description = "Ensure diagnostic settings are configured for key resources"
  severity    = "high"

  query = query.ksi_mla_03_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-MLA-03"
  })
}

control "ksi_mla_04_azure" {
  title       = "KSI-MLA-04: Security Monitoring"
  description = "Ensure Microsoft Defender for Cloud is enabled"
  severity    = "high"

  query = query.ksi_mla_04_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-MLA-04"
  })
}

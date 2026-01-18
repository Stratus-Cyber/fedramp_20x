# KSI-CNA: Cloud Native Architecture Controls - Azure

control "ksi_cna_01_azure" {
  title       = "KSI-CNA-01: Encryption at Rest"
  description = "Ensure data at rest is encrypted"
  severity    = "high"

  query = query.ksi_cna_01_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-CNA-01"
  })
}

control "ksi_cna_02_azure" {
  title       = "KSI-CNA-02: Encryption in Transit"
  description = "Ensure data in transit is encrypted"
  severity    = "high"

  query = query.ksi_cna_02_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-CNA-02"
  })
}

control "ksi_cna_03_azure" {
  title       = "KSI-CNA-03: Network Segmentation"
  description = "Ensure proper network segmentation and access controls"
  severity    = "high"

  query = query.ksi_cna_03_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-CNA-03"
  })
}

control "ksi_cna_04_azure" {
  title       = "KSI-CNA-04: Public Access Restrictions"
  description = "Ensure resources are not publicly accessible unless required"
  severity    = "critical"

  query = query.ksi_cna_04_azure_check

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_id         = "KSI-CNA-04"
  })
}

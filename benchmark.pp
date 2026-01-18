# FedRAMP 20x Key Security Indicators (KSI) Benchmark
# Comprehensive compliance checks across all cloud platforms

# ============================================================================
# COMMON TAGS
# ============================================================================

locals {
  fedramp_common_tags = {
    category  = "Compliance"
    framework = "FedRAMP 20x"
    plugin    = "aws"
  }
}

# ============================================================================
# AGGREGATE BENCHMARK - ALL PLATFORMS
# ============================================================================

benchmark "fedramp_20x_all" {
  title       = "FedRAMP 20x Key Security Indicators - All Platforms"
  description = "Comprehensive FedRAMP 20x KSI compliance status across all enabled platforms"

  children = [
    benchmark.ksi_afr_all,
    benchmark.ksi_ced_all,
    benchmark.ksi_cmt_all,
    benchmark.ksi_cna_all,
    benchmark.ksi_iam_all,
    benchmark.ksi_inr_all,
    benchmark.ksi_mla_all,
    benchmark.ksi_piy_all,
    benchmark.ksi_rpl_all,
    benchmark.ksi_svc_all,
    benchmark.ksi_tpr_all,
  ]

  tags = merge(local.fedramp_common_tags, {
    type = "aggregate"
  })
}

# ============================================================================
# PLATFORM-SPECIFIC ROLLUP BENCHMARKS
# ============================================================================

benchmark "fedramp_20x_aws" {
  title       = "FedRAMP 20x KSI - AWS"
  description = "FedRAMP 20x KSI compliance for AWS platform"

  children = [
    benchmark.ksi_iam_aws,
    benchmark.ksi_cna_aws,
    benchmark.ksi_mla_aws,
    # ... other KSI AWS benchmarks
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    type           = "platform"
  })
}

benchmark "fedramp_20x_azure" {
  title       = "FedRAMP 20x KSI - Azure"
  description = "FedRAMP 20x KSI compliance for Azure platform"

  children = [
    benchmark.ksi_iam_azure,
    benchmark.ksi_cna_azure,
    benchmark.ksi_mla_azure,
    # ... other KSI Azure benchmarks
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    type           = "platform"
  })
}

# ============================================================================
# KSI FAMILY BENCHMARKS - ALL PLATFORMS
# ============================================================================

benchmark "ksi_afr_all" {
  title       = "KSI-AFR: Authorization by FedRAMP - All Platforms"
  description = "Authorization by FedRAMP requirements across all platforms"

  children = [
    # benchmark.ksi_afr_aws,
    # benchmark.ksi_afr_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "AFR"
    type       = "family"
  })
}

benchmark "ksi_ced_all" {
  title       = "KSI-CED: Cybersecurity Education - All Platforms"
  description = "Cybersecurity education and training requirements across all platforms"

  children = [
    # benchmark.ksi_ced_aws,
    # benchmark.ksi_ced_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "CED"
    type       = "family"
  })
}

benchmark "ksi_cmt_all" {
  title       = "KSI-CMT: Change Management - All Platforms"
  description = "Change management requirements across all platforms"

  children = [
    # benchmark.ksi_cmt_aws,
    # benchmark.ksi_cmt_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "CMT"
    type       = "family"
  })
}

benchmark "ksi_cna_all" {
  title       = "KSI-CNA: Cloud Native Architecture - All Platforms"
  description = "Cloud native architecture requirements across all platforms"

  children = [
    # benchmark.ksi_cna_aws,
    # benchmark.ksi_cna_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "CNA"
    type       = "family"
  })
}

benchmark "ksi_iam_all" {
  title       = "KSI-IAM: Identity and Access Management - All Platforms"
  description = "Identity and access management requirements across all platforms"

  children = [
    # benchmark.ksi_iam_aws,
    # benchmark.ksi_iam_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "IAM"
    type       = "family"
  })
}

benchmark "ksi_inr_all" {
  title       = "KSI-INR: Incident Response - All Platforms"
  description = "Incident response requirements across all platforms"

  children = [
    # benchmark.ksi_inr_aws,
    # benchmark.ksi_inr_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "INR"
    type       = "family"
  })
}

benchmark "ksi_mla_all" {
  title       = "KSI-MLA: Monitoring, Logging, Auditing - All Platforms"
  description = "Monitoring, logging, and auditing requirements across all platforms"

  children = [
    # benchmark.ksi_mla_aws,
    # benchmark.ksi_mla_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "MLA"
    type       = "family"
  })
}

benchmark "ksi_piy_all" {
  title       = "KSI-PIY: Policy and Inventory - All Platforms"
  description = "Policy and inventory requirements across all platforms"

  children = [
    # benchmark.ksi_piy_aws,
    # benchmark.ksi_piy_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "PIY"
    type       = "family"
  })
}

benchmark "ksi_rpl_all" {
  title       = "KSI-RPL: Recovery Planning - All Platforms"
  description = "Recovery planning requirements across all platforms"

  children = [
    # benchmark.ksi_rpl_aws,
    # benchmark.ksi_rpl_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "RPL"
    type       = "family"
  })
}

benchmark "ksi_svc_all" {
  title       = "KSI-SVC: Service Configuration - All Platforms"
  description = "Service configuration requirements across all platforms"

  children = [
    # benchmark.ksi_svc_aws,
    # benchmark.ksi_svc_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "SVC"
    type       = "family"
  })
}

benchmark "ksi_tpr_all" {
  title       = "KSI-TPR: Third-Party Resources - All Platforms"
  description = "Third-party resources requirements across all platforms"

  children = [
    # benchmark.ksi_tpr_aws,
    # benchmark.ksi_tpr_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    ksi_family = "TPR"
    type       = "family"
  })
}

# ============================================================================
# KSI PLATFORM-SPECIFIC BENCHMARKS - AWS
# ============================================================================

benchmark "ksi_iam_aws" {
  title       = "KSI-IAM: Identity and Access Management - AWS"
  description = "AWS-specific identity and access management controls"

  children = [
    control.ksi_iam_01_aws,
    control.ksi_iam_02_aws,
    control.ksi_iam_03_aws,
    control.ksi_iam_04_aws,
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_family     = "IAM"
    type           = "platform_family"
  })
}

benchmark "ksi_cna_aws" {
  title       = "KSI-CNA: Cloud Native Architecture - AWS"
  description = "AWS-specific cloud native architecture controls"

  children = [
    control.ksi_cna_01_aws,
    control.ksi_cna_02_aws,
    control.ksi_cna_03_aws,
    control.ksi_cna_04_aws,
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_family     = "CNA"
    type           = "platform_family"
  })
}

benchmark "ksi_mla_aws" {
  title       = "KSI-MLA: Monitoring, Logging, Auditing - AWS"
  description = "AWS-specific monitoring, logging, and auditing controls"

  children = [
    control.ksi_mla_01_aws,
    control.ksi_mla_02_aws,
    control.ksi_mla_03_aws,
    control.ksi_mla_04_aws,
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "aws"
    ksi_family     = "MLA"
    type           = "platform_family"
  })
}

# ============================================================================
# KSI PLATFORM-SPECIFIC BENCHMARKS - AZURE
# ============================================================================

benchmark "ksi_iam_azure" {
  title       = "KSI-IAM: Identity and Access Management - Azure"
  description = "Azure-specific identity and access management controls"

  children = [
    control.ksi_iam_01_azure,
    control.ksi_iam_02_azure,
    control.ksi_iam_03_azure,
    control.ksi_iam_04_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_family     = "IAM"
    type           = "platform_family"
  })
}

benchmark "ksi_cna_azure" {
  title       = "KSI-CNA: Cloud Native Architecture - Azure"
  description = "Azure-specific cloud native architecture controls"

  children = [
    control.ksi_cna_01_azure,
    control.ksi_cna_02_azure,
    control.ksi_cna_03_azure,
    control.ksi_cna_04_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_family     = "CNA"
    type           = "platform_family"
  })
}

benchmark "ksi_mla_azure" {
  title       = "KSI-MLA: Monitoring, Logging, Auditing - Azure"
  description = "Azure-specific monitoring, logging, and auditing controls"

  children = [
    control.ksi_mla_01_azure,
    control.ksi_mla_02_azure,
    control.ksi_mla_03_azure,
    control.ksi_mla_04_azure,
  ]

  tags = merge(local.fedramp_common_tags, {
    cloud_provider = "azure"
    ksi_family     = "MLA"
    type           = "platform_family"
  })
}

# ============================================================================
# CONTROLS AND QUERIES
# ============================================================================
# Controls are defined in:
#   - aws/controls/ksi_iam_aws.pp, aws/controls/ksi_cna_aws.pp, aws/controls/ksi_mla_aws.pp
#   - azure/controls/ksi_iam_azure.pp, azure/controls/ksi_cna_azure.pp, azure/controls/ksi_mla_azure.pp
#
# Queries are defined in:
#   - aws/queries/ksi_iam_aws.pp, aws/queries/ksi_cna_aws.pp, aws/queries/ksi_mla_aws.pp
#   - azure/queries/ksi_iam_azure.pp, azure/queries/ksi_cna_azure.pp, azure/queries/ksi_mla_azure.pp

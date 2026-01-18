# KSI-MLA: Monitoring, Logging, Auditing Queries - Azure

query "ksi_mla_01_azure_check" {
  sql = <<-EOQ
    -- Check Activity Log profile exists
    select
      id as resource,
      case
        when id is not null then 'ok'
        else 'alarm'
      end as status,
      'Activity log profile configured.' as reason,
      subscription_id
    from
      azure_log_profile
  EOQ
}

query "ksi_mla_02_azure_check" {
  sql = <<-EOQ
    -- Check Activity Log retention
    select
      id as resource,
      case
        when retention_policy_enabled and retention_policy_days >= 365 then 'ok'
        when retention_policy_enabled and retention_policy_days > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when retention_policy_enabled and retention_policy_days >= 365 then 'Activity log retention is ' || retention_policy_days || ' days.'
        when retention_policy_enabled and retention_policy_days > 0 then 'Activity log retention is ' || retention_policy_days || ' days (recommend 365+).'
        else 'Activity log retention not configured.'
      end as reason,
      subscription_id
    from
      azure_log_profile
  EOQ
}

query "ksi_mla_03_azure_check" {
  sql = <<-EOQ
    -- Check Key Vault diagnostic settings
    select
      v.id as resource,
      case
        when d.id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when d.id is not null then v.name || ' has diagnostic settings configured.'
        else v.name || ' does not have diagnostic settings configured.'
      end as reason,
      v.resource_group,
      v.subscription_id
    from
      azure_key_vault as v
      left join azure_diagnostic_setting as d on v.id = d.resource_uri
  EOQ
}

query "ksi_mla_04_azure_check" {
  sql = <<-EOQ
    -- Check Microsoft Defender for Cloud pricing tier
    select
      id as resource,
      case
        when pricing_tier = 'Standard' then 'ok'
        else 'alarm'
      end as status,
      case
        when pricing_tier = 'Standard' then name || ' Defender is enabled (Standard tier).'
        else name || ' Defender is not enabled or using Free tier.'
      end as reason,
      subscription_id
    from
      azure_security_center_subscription_pricing
  EOQ
}

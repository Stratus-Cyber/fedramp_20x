# KSI-MLA: Monitoring, Logging, Auditing Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_mla_01_azure_check" {
  sql = <<-EOQ
    -- Check Activity Log retention is at least 365 days (CIS Azure 5.1.1)
    select
      id as resource,
      case
        when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int >= 365 then 'ok'
        when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int >= 365 then name || ' has activity log retention of ' || (retention_policy->>'days') || ' days.'
        when (retention_policy->>'enabled')::boolean and (retention_policy->>'days')::int > 0 then name || ' has activity log retention of ' || (retention_policy->>'days') || ' days (recommend 365+).'
        else name || ' does not have activity log retention configured.'
      end as reason,
      subscription_id
    from
      all_azure.azure_log_profile

    union all

    -- Check diagnostic settings for Key Vault (CIS Azure 5.1.5)
    select
      id as resource,
      case
        when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then name || ' has diagnostic settings enabled.'
        else name || ' does not have diagnostic settings enabled.'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault

    union all

    -- Check diagnostic settings for Network Security Groups (CIS Azure 6.5)
    select
      id as resource,
      case
        when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then 'ok'
        else 'alarm'
      end as status,
      case
        when diagnostic_settings is not null and jsonb_array_length(diagnostic_settings) > 0 then name || ' has diagnostic settings enabled.'
        else name || ' does not have diagnostic settings enabled.'
      end as reason,
      subscription_id
    from
      all_azure.azure_network_security_group

    union all

    -- Check SQL Server (auditing is enabled by default for Azure SQL)
    select
      id as resource,
      'ok' as status,
      name || ' has auditing enabled by default.' as reason,
      subscription_id
    from
      all_azure.azure_sql_server

    union all

    -- Check Log Analytics workspace retention (best practice)
    select
      id as resource,
      case
        when retention_in_days >= 365 then 'ok'
        when retention_in_days > 0 then 'info'
        else 'alarm'
      end as status,
      case
        when retention_in_days >= 365 then name || ' has retention of ' || retention_in_days || ' days.'
        when retention_in_days > 0 then name || ' has retention of ' || retention_in_days || ' days (recommend 365+).'
        else name || ' does not have retention configured.'
      end as reason,
      subscription_id
    from
      all_azure.azure_log_analytics_workspace

    union all

    -- Check Azure Monitor log alerts exist (best practice)
    select
      'subscription-' || subscription_id as resource,
      case
        when count(*) > 0 then 'ok'
        else 'info'
      end as status,
      'Subscription has ' || count(*) || ' log alert rules configured.' as reason,
      subscription_id
    from
      all_azure.azure_log_alert
    group by
      subscription_id
  EOQ
}

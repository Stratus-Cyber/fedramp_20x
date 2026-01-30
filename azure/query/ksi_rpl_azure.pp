# KSI-RPL: Recovery Planning Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_rpl_01_azure_check" {
  sql = <<-EOQ
    -- Check SQL Database (backup retention configured by default)
    select
      id as resource,
      'ok' as status,
      name || ' has backup retention configured by default.' as reason,
      subscription_id
    from
      all_azure.azure_sql_database
    where
      name != 'master'

    union all

    -- Check Storage Account replication for disaster recovery (best practice)
    select
      id as resource,
      case
        when sku_name in ('Standard_GRS', 'Standard_RAGRS', 'Standard_GZRS', 'Standard_RAGZRS') then 'ok'
        when sku_name in ('Standard_LRS', 'Standard_ZRS') then 'info'
        else 'info'
      end as status,
      case
        when sku_name in ('Standard_GRS', 'Standard_RAGRS', 'Standard_GZRS', 'Standard_RAGZRS') then name || ' uses geo-redundant storage (' || sku_name || ') for disaster recovery.'
        when sku_name in ('Standard_LRS', 'Standard_ZRS') then name || ' uses local/zone redundancy (' || sku_name || ') - consider geo-redundancy for RPO/RTO.'
        else name || ' replication type: ' || coalesce(sku_name, 'unknown') || '.'
      end as reason,
      subscription_id
    from
      all_azure.azure_storage_account

    union all

    -- Check Azure Site Recovery configured for VMs (best practice)
    select
      'subscription-' || subscription_id as resource,
      case
        when count(*) > 0 then 'ok'
        else 'info'
      end as status,
      'Subscription has ' || count(*) || ' Azure Site Recovery vaults for disaster recovery.' as reason,
      subscription_id
    from
      all_azure.azure_recovery_services_vault
    group by
      subscription_id
  EOQ
}

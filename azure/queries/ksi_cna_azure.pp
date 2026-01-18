# KSI-CNA: Cloud Native Architecture Queries - Azure

query "ksi_cna_01_azure_check" {
  sql = <<-EOQ
    -- Check Storage Account encryption
    select
      id as resource,
      case
        when encryption_key_source is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when encryption_key_source is not null then name || ' has encryption enabled (' || encryption_key_source || ').'
        else name || ' does not have encryption configured.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account
  EOQ
}

query "ksi_cna_02_azure_check" {
  sql = <<-EOQ
    -- Check Storage Account HTTPS enforcement
    select
      id as resource,
      case
        when enable_https_traffic_only then 'ok'
        else 'alarm'
      end as status,
      case
        when enable_https_traffic_only then name || ' enforces HTTPS.'
        else name || ' does not enforce HTTPS.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account
  EOQ
}

query "ksi_cna_03_azure_check" {
  sql = <<-EOQ
    -- Check NSG rules for overly permissive access
    select
      id as resource,
      case
        when security_rules @> '[{"sourceAddressPrefix": "*", "access": "Allow"}]' then 'alarm'
        else 'ok'
      end as status,
      case
        when security_rules @> '[{"sourceAddressPrefix": "*", "access": "Allow"}]' then name || ' has overly permissive rules.'
        else name || ' has properly restricted rules.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_network_security_group
  EOQ
}

query "ksi_cna_04_azure_check" {
  sql = <<-EOQ
    -- Check Storage Account public access
    select
      id as resource,
      case
        when allow_blob_public_access then 'alarm'
        else 'ok'
      end as status,
      case
        when allow_blob_public_access then name || ' allows public blob access.'
        else name || ' blocks public blob access.'
      end as reason,
      resource_group,
      subscription_id
    from
      azure_storage_account
  EOQ
}

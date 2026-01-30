# KSI-CNA: Cloud Native Architecture Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_cna_01_azure_check" {
  sql = <<-EOQ
    -- Check Network Security Groups have restrictive rules (CIS Azure 6.1, 6.2)
    select
      nsg.id as resource,
      case
        when rule->>'access' = 'Allow'
          and rule->>'direction' = 'Inbound'
          and rule->>'source_address_prefix' in ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
          and rule->>'protocol' in ('*', 'TCP', 'UDP')
          and (
            rule->>'destination_port_range' like '%22%'
            or rule->>'destination_port_range' like '%3389%'
            or rule->>'destination_port_range' = '*'
          ) then 'alarm'
        else 'ok'
      end as status,
      case
        when rule->>'access' = 'Allow'
          and rule->>'direction' = 'Inbound'
          and rule->>'source_address_prefix' in ('*', '0.0.0.0', '0.0.0.0/0', 'Internet', 'any', '<nw>/0', '/0')
          and rule->>'protocol' in ('*', 'TCP', 'UDP')
          and (
            rule->>'destination_port_range' like '%22%'
            or rule->>'destination_port_range' like '%3389%'
            or rule->>'destination_port_range' = '*'
          ) then nsg.name || ' NSG allows unrestricted inbound access on sensitive ports: ' || (rule->>'name') || '.'
        else nsg.name || ' NSG has appropriate inbound restrictions: ' || (rule->>'name') || '.'
      end as reason,
      nsg.subscription_id
    from
      all_azure.azure_network_security_group as nsg,
      jsonb_array_elements(security_rules) as rule

    union all

    -- Check VMs without network security groups (best practice)
    select
      vm.id as resource,
      case
        when nic.network_security_group_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when nic.network_security_group_id is null then vm.name || ' does not have an NSG attached to NIC ' || nic.name || '.'
        else vm.name || ' has NSG protection on NIC ' || nic.name || '.'
      end as reason,
      vm.subscription_id
    from
      all_azure.azure_compute_virtual_machine as vm,
      jsonb_array_elements(network_interfaces) as vm_nic
      join all_azure.azure_network_interface as nic on nic.id = vm_nic ->> 'id'

    union all

    -- Check subnets have network security groups (CIS Azure 6.6)
    select
      id as resource,
      case
        when network_security_group_id is null then 'alarm'
        else 'ok'
      end as status,
      case
        when network_security_group_id is null then name || ' subnet does not have an NSG attached.'
        else name || ' subnet has NSG protection.'
      end as reason,
      subscription_id
    from
      all_azure.azure_subnet
    where
      name != 'GatewaySubnet'
      and name != 'AzureFirewallSubnet'
      and name != 'AzureBastionSubnet'

    union all

    -- Check Application Gateway has Web Application Firewall enabled (CIS Azure 6.7)
    select
      id as resource,
      case
        when web_application_firewall_configuration is not null
          and web_application_firewall_configuration ->> 'enabled' = 'true' then 'ok'
        when sku->>'tier' = 'WAF_v2' or sku->>'tier' = 'WAF' then 'info'
        else 'alarm'
      end as status,
      case
        when web_application_firewall_configuration is not null
          and web_application_firewall_configuration ->> 'enabled' = 'true' then name || ' has WAF enabled.'
        when sku->>'tier' = 'WAF_v2' or sku->>'tier' = 'WAF' then name || ' uses WAF tier (verify configuration).'
        else name || ' does not have WAF enabled.'
      end as reason,
      subscription_id
    from
      all_azure.azure_application_gateway
  EOQ
}

query "ksi_cna_02_azure_check" {
  sql = <<-EOQ
    -- Check VM disks are encrypted (CIS Azure 7.1)
    select
      vm.id as resource,
      case
        when disk.encryption_type is not null then 'ok'
        else 'info'
      end as status,
      case
        when disk.encryption_type is not null then vm.name || ' has disk encryption: ' || disk.encryption_type || '.'
        else vm.name || ' disk encryption status needs review.'
      end as reason,
      vm.subscription_id
    from
      all_azure.azure_compute_virtual_machine as vm
      join all_azure.azure_compute_disk as disk on disk.id = vm.managed_disk_id

    union all

    -- Check SQL Database (TDE is enabled by default for Azure SQL)
    select
      id as resource,
      'ok' as status,
      name || ' has Transparent Data Encryption enabled by default.' as reason,
      subscription_id
    from
      all_azure.azure_sql_database
    where
      name != 'master'

    union all

    -- Check storage accounts use encryption (CIS Azure 3.2)
    -- Note: Azure Storage encryption is enabled by default and cannot be disabled
    select
      id as resource,
      'ok' as status,
      name || ' has encryption enabled (Azure Storage encrypts all data by default).' as reason,
      subscription_id
    from
      all_azure.azure_storage_account

    union all

    -- Check storage accounts use customer-managed keys (best practice)
    select
      id as resource,
      case
        when encryption_key_source = 'Microsoft.Keyvault' then 'ok'
        when encryption_key_source = 'Microsoft.Storage' then 'info'
        else 'info'
      end as status,
      case
        when encryption_key_source = 'Microsoft.Keyvault' then name || ' uses customer-managed keys (CMK).'
        when encryption_key_source = 'Microsoft.Storage' then name || ' uses Microsoft-managed keys (consider CMK).'
        else name || ' encryption key source: ' || encryption_key_source || '.'
      end as reason,
      subscription_id
    from
      all_azure.azure_storage_account

    union all

    -- Check Azure Kubernetes Service (AKS) uses disk encryption (CIS Azure 8.3)
    select
      id as resource,
      case
        when disk_encryption_set_id is not null then 'ok'
        else 'info'
      end as status,
      case
        when disk_encryption_set_id is not null then name || ' uses disk encryption set.'
        else name || ' does not use a disk encryption set (consider enabling).'
      end as reason,
      subscription_id
    from
      all_azure.azure_kubernetes_cluster
  EOQ
}

query "ksi_cna_03_azure_check" {
  sql = <<-EOQ
    -- Check storage accounts allow secure transfer only (CIS Azure 3.1)
    select
      id as resource,
      case
        when enable_https_traffic_only then 'ok'
        else 'alarm'
      end as status,
      case
        when enable_https_traffic_only then name || ' requires secure transfer (HTTPS).'
        else name || ' does not require secure transfer.'
      end as reason,
      subscription_id
    from
      all_azure.azure_storage_account

    union all

    -- Check Application Gateway uses SSL/TLS policies (best practice)
    select
      id as resource,
      case
        when ssl_policy->>'policyType' = 'Predefined'
          and ssl_policy->>'policyName' in ('AppGwSslPolicy20220101', 'AppGwSslPolicy20170401S') then 'ok'
        when ssl_policy->>'policyType' = 'Custom' then 'info'
        else 'alarm'
      end as status,
      case
        when ssl_policy->>'policyType' = 'Predefined'
          and ssl_policy->>'policyName' in ('AppGwSslPolicy20220101', 'AppGwSslPolicy20170401S') then name || ' uses secure SSL policy: ' || (ssl_policy->>'policyName') || '.'
        when ssl_policy->>'policyType' = 'Custom' then name || ' uses custom SSL policy (verify configuration).'
        else name || ' uses outdated SSL policy or no policy configured.'
      end as reason,
      subscription_id
    from
      all_azure.azure_application_gateway
    where
      ssl_policy is not null

    union all

    -- Check Redis Cache uses SSL/TLS (CIS Azure 4.3.1)
    select
      id as resource,
      case
        when enable_non_ssl_port = false then 'ok'
        else 'alarm'
      end as status,
      case
        when enable_non_ssl_port = false then name || ' enforces SSL/TLS only.'
        else name || ' allows non-SSL connections.'
      end as reason,
      subscription_id
    from
      all_azure.azure_redis_cache

    union all

    -- Check PostgreSQL SSL enforcement (CIS Azure 4.3.2)
    select
      id as resource,
      case
        when ssl_enforcement = 'Enabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when ssl_enforcement = 'Enabled' then name || ' enforces SSL connections.'
        else name || ' does not enforce SSL connections.'
      end as reason,
      subscription_id
    from
      all_azure.azure_postgresql_server

    union all

    -- Check MySQL SSL enforcement (CIS Azure 4.3.3)
    select
      id as resource,
      case
        when ssl_enforcement = 'Enabled' then 'ok'
        else 'alarm'
      end as status,
      case
        when ssl_enforcement = 'Enabled' then name || ' enforces SSL connections.'
        else name || ' does not enforce SSL connections.'
      end as reason,
      subscription_id
    from
      all_azure.azure_mysql_server
  EOQ
}

query "ksi_cna_04_azure_check" {
  sql = <<-EOQ
    -- Check VM scale sets use custom images (best practice for immutable infrastructure)
    select
      id as resource,
      case
        when virtual_machine_storage_profile->'imageReference'->>'id' is not null then 'ok'
        else 'info'
      end as status,
      case
        when virtual_machine_storage_profile->'imageReference'->>'id' is not null then name || ' uses custom image (supports immutable infrastructure).'
        else name || ' uses marketplace image (consider custom images for immutability).'
      end as reason,
      subscription_id
    from
      all_azure.azure_compute_virtual_machine_scale_set

    union all

    -- Check AKS uses Azure Policy for pod security (best practice)
    select
      id as resource,
      case
        when addon_profiles -> 'azurepolicy' ->> 'enabled' = 'true' then 'ok'
        else 'info'
      end as status,
      case
        when addon_profiles -> 'azurepolicy' ->> 'enabled' = 'true' then name || ' has Azure Policy addon enabled for pod security.'
        else name || ' does not have Azure Policy addon (consider enabling).'
      end as reason,
      subscription_id
    from
      all_azure.azure_kubernetes_cluster

    union all

    -- Check container registries have admin user disabled (CIS Azure 9.7)
    select
      id as resource,
      case
        when admin_user_enabled then 'alarm'
        else 'ok'
      end as status,
      case
        when admin_user_enabled then name || ' has admin user enabled (should use RBAC/managed identities).'
        else name || ' does not use admin user.'
      end as reason,
      subscription_id
    from
      all_azure.azure_container_registry

    union all

    -- Check App Service uses latest runtime (best practice for immutable infrastructure)
    select
      id as resource,
      case
        when configuration -> 'properties' ->> 'pythonVersion' is not null
          or configuration -> 'properties' ->> 'nodeVersion' is not null
          or configuration -> 'properties' ->> 'phpVersion' is not null
          or configuration -> 'properties' ->> 'javaVersion' is not null then 'info'
        else 'ok'
      end as status,
      case
        when configuration -> 'properties' ->> 'pythonVersion' is not null then name || ' uses Python ' || (configuration -> 'properties' ->> 'pythonVersion') || ' (verify latest).'
        when configuration -> 'properties' ->> 'nodeVersion' is not null then name || ' uses Node.js ' || (configuration -> 'properties' ->> 'nodeVersion') || ' (verify latest).'
        when configuration -> 'properties' ->> 'phpVersion' is not null then name || ' uses PHP ' || (configuration -> 'properties' ->> 'phpVersion') || ' (verify latest).'
        when configuration -> 'properties' ->> 'javaVersion' is not null then name || ' uses Java ' || (configuration -> 'properties' ->> 'javaVersion') || ' (verify latest).'
        else name || ' runtime version verified.'
      end as reason,
      subscription_id
    from
      all_azure.azure_app_service_web_app

    union all

    -- Check storage account public access is disabled (CIS Azure 3.7)
    select
      id as resource,
      case
        when allow_blob_public_access = false then 'ok'
        else 'alarm'
      end as status,
      case
        when allow_blob_public_access = false then name || ' has public blob access disabled.'
        else name || ' allows public blob access.'
      end as reason,
      subscription_id
    from
      all_azure.azure_storage_account
  EOQ
}

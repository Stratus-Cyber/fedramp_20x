# KSI-SVC: Service Configuration Queries - Azure
# Updated for Turbot Pipes workspace schema (all_azure.*)

query "ksi_svc_01_azure_check" {
  sql = <<-EOQ
    -- Check AKS version is current (best practice for security improvements)
    select
      id as resource,
      case
        when kubernetes_version < '1.25' then 'alarm'
        when kubernetes_version < '1.27' then 'info'
        else 'ok'
      end as status,
      case
        when kubernetes_version < '1.25' then name || ' runs outdated Kubernetes ' || kubernetes_version || ' (upgrade for security improvements).'
        when kubernetes_version < '1.27' then name || ' runs Kubernetes ' || kubernetes_version || ' (consider upgrading).'
        else name || ' runs current Kubernetes ' || kubernetes_version || '.'
      end as reason,
      subscription_id
    from
      all_azure.azure_kubernetes_cluster
  EOQ
}

query "ksi_svc_06_azure_check" {
  sql = <<-EOQ
    -- Check Key Vault key rotation policy configured (best practice)
    select
      id as resource,
      case
        when rotation_policy is not null then 'ok'
        else 'info'
      end as status,
      case
        when rotation_policy is not null then name || ' has key rotation policy configured.'
        else name || ' does not have key rotation policy (consider automatic rotation).'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault_key

    union all

    -- Check Key Vault keys have expiration dates (CIS Azure 8.1)
    select
      id as resource,
      case
        when expires_at is not null and expires_at > current_timestamp then 'ok'
        when expires_at is null then 'alarm'
        else 'alarm'
      end as status,
      case
        when expires_at is not null and expires_at > current_timestamp then name || ' has valid expiration date: ' || expires_at::date || '.'
        when expires_at is null then name || ' does not have an expiration date (should rotate regularly).'
        else name || ' has expired (rotate immediately).'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault_key

    union all

    -- Check Key Vault secrets have expiration dates (CIS Azure 8.2)
    select
      id as resource,
      case
        when expires_at is not null and expires_at > current_timestamp then 'ok'
        when expires_at is null then 'alarm'
        else 'alarm'
      end as status,
      case
        when expires_at is not null and expires_at > current_timestamp then name || ' has valid expiration date: ' || expires_at::date || '.'
        when expires_at is null then name || ' does not have an expiration date (should rotate regularly).'
        else name || ' has expired (rotate immediately).'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault_secret

    union all

    -- Check Key Vault certificates expiration (best practice)
    select
      id as resource,
      case
        when expires > (current_timestamp + interval '30 days') then 'ok'
        when expires > current_timestamp then 'info'
        else 'alarm'
      end as status,
      case
        when expires > (current_timestamp + interval '30 days') then name || ' certificate is valid until ' || expires::date || '.'
        when expires > current_timestamp then name || ' certificate expires soon on ' || expires::date || ' (rotate).'
        else name || ' certificate has expired (rotate immediately).'
      end as reason,
      subscription_id
    from
      all_azure.azure_key_vault_certificate

    union all

    -- Check Application Gateway SSL certificates (best practice)
    select
      id as resource,
      case
        when ssl_certificates is not null and jsonb_array_length(ssl_certificates) > 0 then 'info'
        else 'ok'
      end as status,
      name || ' has ' || coalesce(jsonb_array_length(ssl_certificates), 0) || ' SSL certificates configured (verify expiration dates).' as reason,
      subscription_id
    from
      all_azure.azure_application_gateway

    union all

    -- Check Storage Account access keys rotation (best practice)
    select
      id as resource,
      'info' as status,
      name || ' uses storage account keys (rotate regularly - consider using SAS tokens or Azure AD).' as reason,
      subscription_id
    from
      all_azure.azure_storage_account
    where
      primary_blob_endpoint is not null
    limit 10
  EOQ
}

# KSI-IAM: Identity and Access Management Queries - Azure

query "ksi_iam_01_azure_check" {
  sql = <<-EOQ
    -- Check for unique Azure AD user accounts
    select
      id as resource,
      case
        when user_principal_name is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when user_principal_name is not null then display_name || ' is a unique user account.'
        else 'User account issue detected.'
      end as reason,
      tenant_id
    from
      azuread_user
  EOQ
}

query "ksi_iam_02_azure_check" {
  sql = <<-EOQ
    -- Check MFA registration for Azure AD users
    -- Note: Requires additional configuration to query MFA status
    select
      id as resource,
      'info' as status,
      display_name || ' - MFA status requires Azure AD Premium reporting.' as reason,
      tenant_id
    from
      azuread_user
    where
      account_enabled = true
  EOQ
}

query "ksi_iam_03_azure_check" {
  sql = <<-EOQ
    -- Check for guest users
    select
      id as resource,
      case
        when user_type = 'Guest' then 'info'
        else 'ok'
      end as status,
      case
        when user_type = 'Guest' then display_name || ' is a guest user - review access.'
        else display_name || ' is a member user.'
      end as reason,
      tenant_id
    from
      azuread_user
  EOQ
}

query "ksi_iam_04_azure_check" {
  sql = <<-EOQ
    -- Check for users with privileged role assignments
    select
      u.id as resource,
      case
        when r.role_definition_name in ('Global Administrator', 'Privileged Role Administrator') then 'alarm'
        else 'ok'
      end as status,
      case
        when r.role_definition_name in ('Global Administrator', 'Privileged Role Administrator') then u.display_name || ' has ' || r.role_definition_name || ' role.'
        else u.display_name || ' does not have highly privileged roles.'
      end as reason,
      u.tenant_id
    from
      azuread_user as u
      left join azure_role_assignment as r on u.id = r.principal_id
  EOQ
}

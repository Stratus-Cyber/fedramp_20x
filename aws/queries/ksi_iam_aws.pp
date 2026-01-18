# KSI-IAM: Identity and Access Management Queries - AWS

query "ksi_iam_01_aws_check" {
  sql = <<-EOQ
    -- Check for unique IAM user accounts
    select
      arn as resource,
      case
        when name is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when name is not null then name || ' is a unique user account.'
        else 'User account issue detected.'
      end as reason,
      region,
      account_id
    from
      aws_iam_user
  EOQ
}

query "ksi_iam_02_aws_check" {
  sql = <<-EOQ
    -- Check MFA status for IAM users with console access
    select
      arn as resource,
      case
        when password_enabled and not mfa_active then 'alarm'
        when password_enabled and mfa_active then 'ok'
        else 'ok'
      end as status,
      case
        when password_enabled and not mfa_active then name || ' has console access but MFA is not enabled.'
        when password_enabled and mfa_active then name || ' has MFA enabled.'
        else name || ' does not have console access.'
      end as reason,
      region,
      account_id
    from
      aws_iam_user
  EOQ
}

query "ksi_iam_03_aws_check" {
  sql = <<-EOQ
    -- Check access key age (90 day rotation)
    select
      u.arn as resource,
      case
        when k.access_key_id is null then 'ok'
        when k.create_date <= (current_date - interval '90 days') then 'alarm'
        else 'ok'
      end as status,
      case
        when k.access_key_id is null then u.name || ' has no access keys.'
        when k.create_date <= (current_date - interval '90 days') then u.name || ' access key ' || k.access_key_id || ' is ' || extract(day from now() - k.create_date) || ' days old.'
        else u.name || ' access key ' || k.access_key_id || ' is within rotation period.'
      end as reason,
      u.account_id
    from
      aws_iam_user as u
      left join aws_iam_access_key as k on u.name = k.user_name
  EOQ
}

query "ksi_iam_04_aws_check" {
  sql = <<-EOQ
    -- Check for users with administrative privileges
    select
      arn as resource,
      case
        when attached_policy_arns @> '["arn:aws:iam::aws:policy/AdministratorAccess"]' then 'alarm'
        else 'ok'
      end as status,
      case
        when attached_policy_arns @> '["arn:aws:iam::aws:policy/AdministratorAccess"]' then name || ' has AdministratorAccess policy attached.'
        else name || ' does not have direct AdministratorAccess.'
      end as reason,
      region,
      account_id
    from
      aws_iam_user
  EOQ
}

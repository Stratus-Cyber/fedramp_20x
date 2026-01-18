# KSI-CNA: Cloud Native Architecture Queries - AWS

query "ksi_cna_01_aws_check" {
  sql = <<-EOQ
    -- Check S3 bucket encryption
    select
      arn as resource,
      case
        when server_side_encryption_configuration is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when server_side_encryption_configuration is not null then name || ' has encryption enabled.'
        else name || ' does not have encryption enabled.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket
  EOQ
}

query "ksi_cna_02_aws_check" {
  sql = <<-EOQ
    -- Check S3 bucket SSL enforcement
    select
      arn as resource,
      case
        when policy::jsonb @> '[{"Condition": {"Bool": {"aws:SecureTransport": "false"}}}]' then 'ok'
        else 'info'
      end as status,
      case
        when policy::jsonb @> '[{"Condition": {"Bool": {"aws:SecureTransport": "false"}}}]' then name || ' enforces SSL.'
        else name || ' SSL enforcement not explicitly configured in bucket policy.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket
  EOQ
}

query "ksi_cna_03_aws_check" {
  sql = <<-EOQ
    -- Check VPC default security group restrictions
    select
      arn as resource,
      case
        when jsonb_array_length(ip_permissions) = 0 and jsonb_array_length(ip_permissions_egress) = 0 then 'ok'
        when group_name = 'default' then 'alarm'
        else 'ok'
      end as status,
      case
        when jsonb_array_length(ip_permissions) = 0 and jsonb_array_length(ip_permissions_egress) = 0 then group_id || ' has no inbound or outbound rules.'
        when group_name = 'default' then group_id || ' default security group has rules configured.'
        else group_id || ' is properly configured.'
      end as reason,
      region,
      account_id
    from
      aws_vpc_security_group
    where
      group_name = 'default'
  EOQ
}

query "ksi_cna_04_aws_check" {
  sql = <<-EOQ
    -- Check S3 bucket public access
    select
      arn as resource,
      case
        when block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets then 'ok'
        else 'alarm'
      end as status,
      case
        when block_public_acls and block_public_policy and ignore_public_acls and restrict_public_buckets then name || ' blocks public access.'
        else name || ' does not fully block public access.'
      end as reason,
      region,
      account_id
    from
      aws_s3_bucket
  EOQ
}

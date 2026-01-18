# KSI-MLA: Monitoring, Logging, Auditing Queries - AWS

query "ksi_mla_01_aws_check" {
  sql = <<-EOQ
    -- Check CloudTrail is enabled
    select
      arn as resource,
      case
        when is_logging then 'ok'
        else 'alarm'
      end as status,
      case
        when is_logging then name || ' is logging.'
        else name || ' is not logging.'
      end as reason,
      region,
      account_id
    from
      aws_cloudtrail_trail
    where
      is_multi_region_trail
  EOQ
}

query "ksi_mla_02_aws_check" {
  sql = <<-EOQ
    -- Check CloudTrail log encryption
    select
      arn as resource,
      case
        when kms_key_id is not null then 'ok'
        else 'alarm'
      end as status,
      case
        when kms_key_id is not null then name || ' logs are encrypted with KMS.'
        else name || ' logs are not encrypted with KMS.'
      end as reason,
      region,
      account_id
    from
      aws_cloudtrail_trail
    where
      is_multi_region_trail
  EOQ
}

query "ksi_mla_03_aws_check" {
  sql = <<-EOQ
    -- Check CloudTrail log file validation
    select
      arn as resource,
      case
        when log_file_validation_enabled then 'ok'
        else 'alarm'
      end as status,
      case
        when log_file_validation_enabled then name || ' has log file validation enabled.'
        else name || ' does not have log file validation enabled.'
      end as reason,
      region,
      account_id
    from
      aws_cloudtrail_trail
    where
      is_multi_region_trail
  EOQ
}

query "ksi_mla_04_aws_check" {
  sql = <<-EOQ
    -- Check GuardDuty is enabled
    select
      'arn:aws:guardduty:' || region || ':' || account_id || ':detector/' || detector_id as resource,
      case
        when status = 'ENABLED' then 'ok'
        else 'alarm'
      end as status,
      case
        when status = 'ENABLED' then 'GuardDuty is enabled in ' || region || '.'
        else 'GuardDuty is not enabled in ' || region || '.'
      end as reason,
      region,
      account_id
    from
      aws_guardduty_detector
  EOQ
}

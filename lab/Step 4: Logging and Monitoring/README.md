# Objective
Even with hardened accounts and strict IAM, attackers may still find a way in (via phishing, misconfigurations, or stolen tokens). To detect and respond to such activity, we must implement logging and monitoring.

Specifically, this step ensures:

1. All API activity is logged (via CloudTrail) for accountability and forensic analysis.
2. System metrics & alarms are monitored (via CloudWatch) so suspicious patterns are detected in real time.
3. Threat intelligence & anomaly detection is applied (via GuardDuty) to highlight malicious behavior like port scans, unusual logins, or data exfiltration.

# Actions to Take
## 1. Enable CloudTrail (API logging)

- Create a multi-region CloudTrail trail.
- Store logs in a dedicated S3 bucket with encryption.
- Enable log file validation (detects tampering).

#### Firstly, we create a bucket for Cloudtrail logs
```bash
aws s3 mb s3://my-cloudtrail-logs-406214277032
```
#### Then we create a multi-region trail
  
#### I initially attempted to create the trail directly:
```bash
aws cloudtrail create-trail --name OrgTrail --s3-bucket-name my-cloudtrail-logs-406214277032 --is-multi-region-trail --enable-log-file-validation
```

#### This failed with the following error:
```bash
An error occurred (InsufficientS3BucketPolicyException) when calling the CreateTrail operation: Incorrect S3 bucket policy is detected for bucket: my-cloudtrail-logs-406214277032
```
This revealed that CloudTrail requires explicit permissions on the bucket in order to write logs.

## 2. Fix Bucket Policy
To resolve this, I attached a bucket policy granting CloudTrail the necessary permissions:
```bash
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck20150319",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::my-cloudtrail-logs-406214277032"
    },
    {
      "Sid": "AWSCloudTrailWrite20150319",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::my-cloudtrail-logs-406214277032/AWSLogs/406214277032/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
```

## 3. Create the Cloudtrail
After applying the policy, I successfully created the Cloudtrail:
```bash
aws cloudtrail create-trail --name OrgTrail --s3-bucket-name my-cloudtrail-logs-406214277032 --is-multi-region-trail --enable-log-file-validation
```
This enabled logging for all AWS regions, ensuring full visibility into API calls and user actions across the environment.

Troubleshooting AWS Config Setup

Initially, when attempting to start the configuration recorder, I encountered the following error:
```bash
An error occurred (NoAvailableDeliveryChannelException) when calling the StartConfigurationRecorder operation: Delivery channel is not available to start configuration recorder.
```

This indicated that while the recorder was successfully created, AWS Config had no defined delivery channel to send configuration snapshots and change notifications.

## 4. Create the Delivery Channel
To resolve this, I created a delivery channel that points to the existing CloudTrail logs bucket:
```bash
aws configservice put-delivery-channel --delivery-channel "{\"name\":\"default\",\"s3BucketName\":\"my-cloudtrail-logs-406214277032\"}"
```

However, this failed with:

```bash
An error occurred (InsufficientDeliveryPolicyException) when calling the PutDeliveryChannel operation: Insufficient delivery policy to s3 bucket
```

This error occurred because AWS Config; like CloudTrail, requires explicit write permissions to the S3 bucket. To fix this, I updated my bucket policy to also include permissions for the config.amazonaws.com service.
After updating my policy file and successfully creating the delivery channel, I started the configuration recorder:

```bash
aws configservice start-configuration-recorder --configuration-recorder-name default
```

This confirmed that AWS Config is now continuously recording configuration changes across all resources, with all snapshots stored securely in the same logging bucket.

# CONCLUSION

Since I’m currently using the AWS free tier, I wasn’t able to enable services like GuardDuty, Security Hub, or Macie because they require paid subscriptions. However, with CloudTrail, AWS Config, and CloudWatch already set up, I still achieved strong visibility and monitoring within my environment. Together, these tools let me log all API activity, track configuration changes, and set up alerts for suspicious behavior; giving me a solid foundation for continuous monitoring even without the premium threat detection features.


  

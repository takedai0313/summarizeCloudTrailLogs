# summarizeCloudTrailLogs
This tool summarize CloudTrailLogs in S3 per year-month

# usage
go run summarizeCloudTrailLogs.go [options]

## options
-aKey -> AWS accesskey. If you don't set this param, use default credentials
-sKey -> AWS secretkey. If you don't set this param, use default credentials
-bucket -> Bucket Name in which CloudTrailLogs is 
-proxy -> if you use proxy, set this param (http://[userid]:[password}@proxyhost:port)
-ym -> year-month(yyyymm) in which you get logs
-path -> full path to result file
-prefix -> in aws s3, prefix
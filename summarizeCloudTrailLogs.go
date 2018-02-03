package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/antonholmquist/jason"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/endpoints"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
)

func initializeResultFile(filepath string) (string, error) {
	_, err := os.Stat(filepath)
	if err == nil {
		// if specified file is existed, delete file
		err := os.Remove(filepath)
		if err != nil {
			return "err", err
		}
	}

	return "nil", nil
}

func writeLogsToFile(writer *bufio.Writer, msg ...string) error {
	_, err := writer.WriteString((strings.Join(msg, ",")) + "\n")
	writer.Flush()

	return err
}

func getRegions() (map[string]endpoints.Region, error) {
	resolver := endpoints.DefaultResolver()
	partitions := resolver.(endpoints.EnumPartitions).Partitions()
	for _, p := range partitions {
		if p.ID() == "aws" {
			return p.Regions(), nil
		}
	}

	return nil, errors.New("failed to get Regions")
}

func createSession(accesskey string, secretkey string, proxy string) (*session.Session, error) {
	var conf aws.Config

	// set aws Region
	conf.Region = aws.String("ap-northeast-1")

	// if you specify, set the accesskey and the secretkey
	if (accesskey != "") && (secretkey != "") {
		conf.Credentials = credentials.NewStaticCredentials(accesskey, secretkey, "")
	}

	// if you specify, set proxy setting
	if proxy != "" {
		httpclient := &http.Client{
			Transport: &http.Transport{
				Proxy: func(*http.Request) (*url.URL, error) {
					return url.Parse(proxy)
				},
			},
		}

		conf.HTTPClient = httpclient
	}

	return session.NewSession(&conf)
}

func listObjects(svc *s3.S3, bucketName string, prefix string, regionName string, yearmonth string, ContinuationToken string) (*s3.ListObjectsV2Output, error) {
	var input s3.ListObjectsV2Input

	input.Bucket = aws.String(bucketName)
	input.Prefix = aws.String(prefix + regionName + "/" + yearmonth[0:4] + "/" + yearmonth[4:6] + "/")
	input.MaxKeys = aws.Int64(100)

	if ContinuationToken != "" {
		input.ContinuationToken = aws.String(ContinuationToken)
	}

	return svc.ListObjectsV2(&input)

}

func getCloudTrailLog(file *os.File, svc *s3.S3, bucket string, key string, filepath string) error {
	getCloudTrailLogInput := &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	}

	result, err := svc.GetObject(getCloudTrailLogInput)
	if err != nil {
		return nil
	}

	v, err := jason.NewObjectFromReader(result.Body)
	records, _ := v.GetObjectArray("Records")
	for _, record := range records {
		// if errors exist, ignore it
		eventTime, _ := record.GetString("eventTime")
		OperationUser, _ := record.GetString("userIdentity", "principalId")
		eventSource, _ := record.GetString("eventSource")
		eventName, _ := record.GetString("eventName")
		awsRegion, _ := record.GetString("awsRegion")
		sourceIPAddress, _ := record.GetString("sourceIPAddress")
		userAgent, _ := record.GetString("userAgent")

		writeLogsToFile(bufio.NewWriter(file), []string{eventTime, OperationUser, eventSource, eventName, awsRegion, sourceIPAddress, userAgent}...)
	}

	return nil
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix("[get AWS-Cloudtrail-Logs] ")
	log.Println("start getAWSCloudtrailLogs")

	var (
		bucketName        string
		accesskey         string
		secretkey         string
		proxy             string
		yearmonth         string
		filepath          string
		costprefixKey     string
		ContinuationToken string
	)

	flag.StringVar(&bucketName, "bucket", "", "Bucket Name to get logs")
	flag.StringVar(&accesskey, "aKey", "", "AWS accesskey(if you don't specify this, use default credentials)")
	flag.StringVar(&secretkey, "sKey", "", "AWS secretkey(if you don't specify this, use default credentials)")
	flag.StringVar(&proxy, "proxy", "", "http://user:pass@proxyhost:port - if you specify this, use aws go-sdk with proxy")
	flag.StringVar(&yearmonth, "ym", "201801", "yyyymm - you want to get logs in this yearmonth")
	flag.StringVar(&filepath, "path", "./result.csv", "full path to result file")
	flag.StringVar(&costprefixKey, "prefix", "", "part of key-prefix which is fixed value([this arg]/[RegionName]/[yyyy]/[mm])")
	flag.Parse()

	log.Println("start to get AWS Regions")
	regions, err := getRegions()
	if err != nil {
		exitErrorf("Unable to get Regions, %v", err)
	}

	log.Println("start to create session to AWS")
	sess, err := createSession(accesskey, secretkey, proxy)
	if err != nil {
		exitErrorf("failed to connect session, %v", err)
	}

	svc := s3.New(sess)

	st, err := initializeResultFile(filepath)
	if err != nil {
		exitErrorf(st+"failed to initialize resultfile, %v", err)
	}

	file, err := os.OpenFile(filepath, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
	defer file.Close()
	if err != nil {
		exitErrorf("failed to write header to file, %v", err)
	}

	writeLogsToFile(bufio.NewWriter(file), []string{"EventTime", "OperationUser", "eventSource", "eventName", "awsRegion", "sourceIPAddress", "userAgent"}...)

	for id, _ := range regions {
		ContinuationToken = ""
		log.Println("getting CloudtrailLog in AWS-Region:" + id + " ...")
		for {
			result, err := listObjects(svc, bucketName, costprefixKey, id, yearmonth, ContinuationToken)
			if err != nil {
				exitErrorf("Unable to list buckets, %v", err)
			}

			for _, content := range result.Contents {
				err := getCloudTrailLog(file, svc, bucketName, *(content.Key), filepath)
				if err != nil {
					exitErrorf("Unable to getObject and Write Log, %v", err)
				}
			}

			if *(result.IsTruncated) == false {
				break
			} else {
				ContinuationToken = *(result.NextContinuationToken)
			}
		}
		log.Println("complete to get AWS Logs in AWS-Region:" + id)
	}
}

// If there's an error, display it.
func exitErrorf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

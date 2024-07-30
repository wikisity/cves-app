#!/usr/bin/env bash

# Exit when any command fails
set -e

# Run this script from root folder. See commands 1) and 2) below to run this file:
#1) chmod +x test-backend.sh 
#2) ./test-backend.sh us-east-1
# Note that us-east-1 region is passed as 1st argument. I defines the region where this template is being deployed in

TEST_BUCKET="test-bucket-$(uuidgen | tr '[:upper:]' '[:lower:]')"
STACK_NAME="betest-stack-$(uuidgen | tr '[:upper:]' '[:lower:]')"
DEPTEST_BUCKET_NAME="deptest-bucket-$(uuidgen | tr '[:upper:]' '[:lower:]')"
REGION=$1

echo "Creating a temporary bucket to host your function CodeUri..."
aws s3api create-bucket --bucket ${TEST_BUCKET} --region ${REGION}

echo "Building your Cloudformation Backend..."

# We aren't using any library that requires compilation right now
# Skip the build step to minimize deployment time.
#sam build --use-container


aws cloudformation package \
    --template-file test-template.yaml \
    --output-template-file test-packaged.yaml \
    --s3-bucket ${TEST_BUCKET}

aws cloudformation deploy \
    --template-file test-packaged.yaml \
    --stack-name ${STACK_NAME} \
    --capabilities CAPABILITY_NAMED_IAM \
    --parameter-overrides \
    depBucketName=${DEPTEST_BUCKET_NAME} \
    --no-fail-on-empty-changeset


echo "Backend Stack Name: ${STACK_NAME}"
import boto3
import json
import os
from datetime import datetime

s3 = boto3.client('s3')

QUARANTINE_BUCKET = os.environ.get('QUARANTINE_BUCKET', '')

def lambda_handler(event, context):
    
    # Parsing the SNS payload
    sns_message = event['Records'][0]['Sns']['Message']
    sns_message_clean = sns_message.replace("'", "\"")
    data = json.loads(sns_message_clean)
    
    # Get the scanning result
    scanning_result = data['scanning_result']
    found_malwares = scanning_result['foundMalwares']
    file_name = scanning_result['fileName']
    scan_result_code = scanning_result['scanResult']
    scan_timestamp = scanning_result['scanTimestamp']
    
    # Get bucket and object from file_url
    file_url = data['file_url']
    bucket_name = file_url.split('//')[-1].split('.')[0]
    
    print(f"Processing file: {file_name} in bucket: {bucket_name}")
    print(f"Found malwares: {found_malwares}")
    print(f"Scan result code: {scan_result_code}")
    
    # Function to publish tags
    def publish_tag(tag, bucket=bucket_name, key=file_name):
        response = s3.put_object_tagging(
            Bucket=bucket,
            Key=key,
            Tagging={'TagSet': tag}
        )
        return response

    def get_existing_tags(bucket, key):
        try:
            existing_tags = s3.get_object_tagging(Bucket=bucket, Key=key)['TagSet']
        except:
            existing_tags = []
        return existing_tags

    def quarantine_object(source_bucket, source_key, quarantine_bucket):
        """
        Move malicious object to quarantine bucket.
        Preserves origin info in path: {quarantine_bucket}/{source_bucket}/{source_key}
        """
        quarantine_key = f"{source_bucket}/{source_key}"

        print(f"Quarantining object: s3://{source_bucket}/{source_key} -> s3://{quarantine_bucket}/{quarantine_key}")

        try:
            # Copy object to quarantine bucket
            copy_source = {'Bucket': source_bucket, 'Key': source_key}
            s3.copy_object(
                CopySource=copy_source,
                Bucket=quarantine_bucket,
                Key=quarantine_key
            )
            print(f"Successfully copied to quarantine: s3://{quarantine_bucket}/{quarantine_key}")

            # Delete original object after successful copy
            s3.delete_object(Bucket=source_bucket, Key=source_key)
            print(f"Successfully deleted original: s3://{source_bucket}/{source_key}")

            return True, quarantine_key
        except Exception as e:
            print(f"Error quarantining object: {str(e)}")
            return False, str(e)
    
    # Convert scan timestamp to readable format
    scan_datetime = datetime.fromisoformat(scan_timestamp.replace('Z', '+00:00'))
    scan_date_formatted = scan_datetime.strftime('%Y/%m/%d %H:%M:%S')
    
    # Function to sanitize tag values for S3 compatibility
    def sanitize_tag_value(value):
        # S3 tag values can only contain: alphanumeric, spaces, and _ . : / = + - @
        # Allowed characters: a-z, A-Z, 0-9, space, _, ., :, /, =, +, -, @
        import re
        
        # Convert to string and replace common invalid characters
        sanitized = str(value)
        
        # Replace invalid characters with safe alternatives
        sanitized = sanitized.replace(',', ' ')  # Replace comma with space
        sanitized = sanitized.replace('(', ' ')  # Replace parentheses with space
        sanitized = sanitized.replace(')', ' ')  # Replace parentheses with space
        sanitized = sanitized.replace('[', ' ')  # Replace brackets with space
        sanitized = sanitized.replace(']', ' ')  # Replace brackets with space
        sanitized = sanitized.replace('{', ' ')  # Replace braces with space
        sanitized = sanitized.replace('}', ' ')  # Replace braces with space
        sanitized = sanitized.replace("'", '')   # Remove single quotes
        sanitized = sanitized.replace('"', '')   # Remove double quotes
        sanitized = sanitized.replace('\n', ' ') # Replace newlines with space
        sanitized = sanitized.replace('\r', ' ') # Replace carriage returns with space
        sanitized = sanitized.replace('\t', ' ') # Replace tabs with space
        
        # Keep only allowed characters: alphanumeric, space, and _ . : / = + - @
        sanitized = re.sub(r'[^a-zA-Z0-9 _.:/=+\-@]', '', sanitized)
        
        # Clean up multiple spaces
        sanitized = re.sub(r'\s+', ' ', sanitized)
        
        # Strip leading/trailing spaces
        sanitized = sanitized.strip()
        
        # Limit length to 256 characters (S3 tag value limit)
        return sanitized[:256]
    
    # Determine scan result message based on scan result code and found malwares
    is_malicious = False
    if scan_result_code == 0 and found_malwares == []:
        # Clean file
        scan_result_message = "no issues found"
        scan_detail_message = "-"
    elif scan_result_code == 1 or found_malwares != []:
        # Malicious file
        scan_result_message = "malicious"
        scan_detail_message = "-"
        is_malicious = True
    else:
        # Handle edge cases
        scan_result_message = "unknown"
        scan_detail_message = f"Scan code: {scan_result_code}, Malwares: {len(found_malwares)}"
        scan_detail_message = sanitize_tag_value(scan_detail_message)

    # Track where we'll apply tags (changes if quarantined)
    tag_bucket = bucket_name
    tag_key = file_name
    quarantined = False

    # Quarantine malicious files if quarantine bucket is configured
    if is_malicious and QUARANTINE_BUCKET:
        print(f"Malicious file detected and quarantine bucket configured: {QUARANTINE_BUCKET}")
        success, result = quarantine_object(bucket_name, file_name, QUARANTINE_BUCKET)
        if success:
            quarantined = True
            tag_bucket = QUARANTINE_BUCKET
            tag_key = result  # The new key in quarantine bucket
            print(f"File quarantined successfully. Will apply tags to quarantined object.")
        else:
            print(f"Quarantine failed: {result}. Will apply tags to original object.")

    # Define new tags in your preferred format (all values sanitized)
    new_tags = [
        {'Key': 'fss-scan-detail-code', 'Value': sanitize_tag_value(str(scan_result_code))},
        {'Key': 'fss-scan-date', 'Value': sanitize_tag_value(scan_date_formatted)},
        {'Key': 'fss-scan-result', 'Value': sanitize_tag_value(scan_result_message)},
        {'Key': 'fss-scan-detail-message', 'Value': scan_detail_message},  # Already sanitized above
        {'Key': 'fss-scanned', 'Value': sanitize_tag_value('true')}
    ]

    # Add quarantine info tags if quarantined
    if quarantined:
        new_tags.append({'Key': 'fss-quarantined', 'Value': 'true'})
        new_tags.append({'Key': 'fss-source-bucket', 'Value': sanitize_tag_value(bucket_name)})

    # Get existing tags (from the target location)
    current_tags = get_existing_tags(tag_bucket, tag_key)

    # Remove any existing fss- tags to avoid duplicates
    def remove_fss_tags(tags):
        return [tag for tag in tags if not tag['Key'].startswith('fss-')]

    # Clean existing tags and add new ones
    cleaned_tags = remove_fss_tags(current_tags)
    final_tags = cleaned_tags + new_tags

    # Debug: Print tag values before applying
    print(f"About to apply tags to {tag_key} in bucket {tag_bucket}:")
    for tag in new_tags:
        print(f"  {tag['Key']}: '{tag['Value']}' (length: {len(tag['Value'])})")
        # Debug: Show any non-ASCII characters
        non_ascii = [c for c in tag['Value'] if ord(c) > 127]
        if non_ascii:
            print(f"    Non-ASCII characters found: {non_ascii}")
        # Debug: Show any characters not in allowed set
        allowed_chars = set('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 _.:/=+-@')
        invalid_chars = [c for c in tag['Value'] if c not in allowed_chars]
        if invalid_chars:
            print(f"    Invalid characters found: {invalid_chars}")

    # Check if we're within the 10 tag limit
    if len(final_tags) <= 10:
        try:
            publish_tag(final_tags, bucket=tag_bucket, key=tag_key)
            print(f"Successfully applied tags to {tag_key} in bucket {tag_bucket}")
        except Exception as e:
            print(f"Error applying tags to {tag_key}: {str(e)}")
            print(f"Tag values that caused the error:")
            for tag in new_tags:
                print(f"  {tag['Key']}: '{tag['Value']}'")
            raise e
    else:
        print(f"Cannot apply tags - would exceed 10 tag limit. Current tags: {len(cleaned_tags)}, New tags: {len(new_tags)}")

    result_message = f'Tagging completed for {file_name}'
    if quarantined:
        result_message = f'File quarantined and tagged: {tag_bucket}/{tag_key}'

    return {
        'statusCode': 200,
        'body': json.dumps(result_message)
    }

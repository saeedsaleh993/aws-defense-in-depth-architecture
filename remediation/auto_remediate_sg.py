import json
import boto3

# استدعاء عميل خدمة EC2 للتحكم في إعدادات الشبكة والـ Security Groups
ec2 = boto3.client('ec2')

def lambda_handler(event, context):
    print("Received Security Event:", json.dumps(event))
    
    # 1. استخراج رقم الـ Security Group المخالف من بيانات الحدث (Dictionary)
    detail = event.get('detail', {})
    sg_id = detail.get('resourceId')
    
    # التحقق من وجود رقم صحيح يبدأ بـ sg-
    if not sg_id or not sg_id.startswith('sg-'):
        print("No valid Security Group ID found.")
        return {"status": "skipped"}

    # 2. جلب تفاصيل القواعد الحالية للـ Security Group من AWS
    response = ec2.describe_security_groups(GroupIds=[sg_id])
    sg = response['SecurityGroups'][0]

    # 3. المرور على كل القواعد (Loop) وفحص المنافذ الخطرة المفتوحة للعالم (0.0.0.0/0)
    for rule in sg.get('IpPermissions', []):
        from_port = rule.get('FromPort')
        
        for ip_range in rule.get('IpRanges', []):
            if ip_range.get('CidrIp') == '0.0.0.0/0' and from_port in [22, 3389]:
                # 4. حذف القاعدة المخالفة فوراً لإغلاق الثغرة تلقائياً
                ec2.revoke_security_group_ingress(
                    GroupId=sg_id,
                    IpPermissions=[rule]
                )
                print(f"REMEDIATED: Closed port {from_port} on {sg_id}")

    return {
        "statusCode": 200,
        "body": json.dumps(f"Security check completed for {sg_id}")
    }
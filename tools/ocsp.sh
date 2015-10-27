#!/bin/sh
# luocheng@baidu.com @ 2014.10.24
# 
# the main functionality of this script is to update ocsp stapling file
# 
# it works as follows:
# 1, get certificate of the specified domain and save certificate chain as level[0-2].crt
# 2, get subject and issuer of baidu's own certificate
# 3, get ocsp stapling file from ocsp url and save it in output/

# modification history:
# --------------------
# 2015/1/6, by Zhang Weiwei, 
# 1. get root cert from Windows cert store and add it to CAbundle.crt, this can erase ocsp response verify failure
# 2. check ocsp response verify result and cert status, if neither is failed, DO NOT update domain.staple file
#

PATH=$PATH:/usr/local/ssl/bin/

ROOTCERT="-----BEGIN CERTIFICATE-----
MIIE0zCCA7ugAwIBAgIQGNrRniZ96LtKIVjNzGs7SjANBgkqhkiG9w0BAQUFADCB
yjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQL
ExZWZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJp
U2lnbiwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxW
ZXJpU2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0
aG9yaXR5IC0gRzUwHhcNMDYxMTA4MDAwMDAwWhcNMzYwNzE2MjM1OTU5WjCByjEL
MAkGA1UEBhMCVVMxFzAVBgNVBAoTDlZlcmlTaWduLCBJbmMuMR8wHQYDVQQLExZW
ZXJpU2lnbiBUcnVzdCBOZXR3b3JrMTowOAYDVQQLEzEoYykgMjAwNiBWZXJpU2ln
biwgSW5jLiAtIEZvciBhdXRob3JpemVkIHVzZSBvbmx5MUUwQwYDVQQDEzxWZXJp
U2lnbiBDbGFzcyAzIFB1YmxpYyBQcmltYXJ5IENlcnRpZmljYXRpb24gQXV0aG9y
aXR5IC0gRzUwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCvJAgIKXo1
nmAMqudLO07cfLw8RRy7K+D+KQL5VwijZIUVJ/XxrcgxiV0i6CqqpkKzj/i5Vbex
t0uz/o9+B1fs70PbZmIVYc9gDaTY3vjgw2IIPVQT60nKWVSFJuUrjxuf6/WhkcIz
SdhDY2pSS9KP6HBRTdGJaXvHcPaz3BJ023tdS1bTlr8Vd6Gw9KIl8q8ckmcY5fQG
BO+QueQA5N06tRn/Arr0PO7gi+s3i+z016zy9vA9r911kTMZHRxAy3QkGSGT2RT+
rCpSx4/VBEnkjWNHiDxpg8v+R70rfk/Fla4OndTRQ8Bnc+MUCH7lP59zuDMKz10/
NIeWiu5T6CUVAgMBAAGjgbIwga8wDwYDVR0TAQH/BAUwAwEB/zAOBgNVHQ8BAf8E
BAMCAQYwbQYIKwYBBQUHAQwEYTBfoV2gWzBZMFcwVRYJaW1hZ2UvZ2lmMCEwHzAH
BgUrDgMCGgQUj+XTGoasjY5rw8+AatRIGCx7GS4wJRYjaHR0cDovL2xvZ28udmVy
aXNpZ24uY29tL3ZzbG9nby5naWYwHQYDVR0OBBYEFH/TZafC3ey78DAJ80M5+gKv
MzEzMA0GCSqGSIb3DQEBBQUAA4IBAQCTJEowX2LP2BqYLz3q3JktvXf2pXkiOOzE
p6B4Eq1iDkVwZMXnl2YtmAl+X6/WzChl8gGqCBpH3vn5fJJaCGkgDdk+bW48DW7Y
5gaRQBi5+MHt39tBquCWIMnNZBU4gcmU7qKEKQsTb47bDN0lAtukixlE0kF6BWlK
WE9gyn6CagsCqiUXObXbf+eEZSqVir2G3l6BFoMtEMze/aiCKm0oHw0LxOXnGiYZ
4fQRbxC1lfznQgUy286dUV4otp6F01vvpX1FQHKOtw5rDgb7MzVIcbidJ4vEZV8N
hnacRHr2lVz2XTIIM6RUthg/aFzyQkqFOFSDX9HoLPKsEdao7WNq
-----END CERTIFICATE-----"

if [ $# -ne 1 ];then
    echo "please specify the domain name"
    exit -1
fi

domain_name=$1

#check healthy of the domain name
curl $domain_name:443>/dev/null 2>&1
if [ $? -ne 0 ]
then
    echo "fail to connect "$domain_name""
    exit -1;
fi

[ ! -d $domain_name ] && mkdir $domain_name

#get certificate chain of the domain name
cd $domain_name
openssl s_client -showcerts -connect $domain_name:443</dev/null | awk -v c=-1 '/-----BEGIN CERTIFICATE-----/{inc=1;c++} inc {print > ("level" c ".crt")} /---END CERTIFICATE-----/{inc=0}'

if [ $? -ne 0 ];then 
    echo "fail to connect "$domain_name""
    exit -1;
fi

#find baidu'own certificate
for crt in level?.crt; 
do 
    if openssl x509 -noout -subject -in "$crt"|grep -i "Baidu";
    then
        cp $crt baidu.crt   
    fi
    echo; 
done 

[ ! -f baidu.crt ] && echo "no baidu.crt" && exit -1;

#find the issuer of baidu's certificate
baidu_issuer=`openssl x509 -noout -issuer -in baidu.crt|sed 's/^issuer= //g'`
if [ -z "$baidu_issuer" ];then
    baidu_issuer="/C=US/O=VeriSign, Inc./OU=VeriSign Trust Network/OU=Terms of use at https://www.verisign.com/rpa (c)10/CN=VeriSign Class 3 Secure Server CA - G3" 
fi

#find certificate  of the issuer
for crt in level?.crt; 
do
    subject=`openssl x509 -noout -subject -in $crt`
    if echo $subject |grep "$baidu_issuer";then
        cp $crt baidu_issuer.crt
    fi
done 

[ ! -f baidu_issuer.crt ] && echo "no baidu_issuer.crt" && exit -1;

echo "$ROOTCERT" > CAbundle.crt
cat level?.crt>>CAbundle.crt

#find the ocsp url
ocsp_url=`openssl x509 -noout -ocsp_uri -in baidu.crt`
if [ -z "$ocsp_url" ];then
    ocsp_url="http://sd.symcd.com"
fi

#make the ocsp stapling file
[ ! -d output ] && mkdir output
openssl ocsp -no_nonce  -issuer baidu_issuer.crt -CAfile CAbundle.crt -cert baidu.crt -VAfile baidu_issuer.crt -url $ocsp_url -respout ./output/domain.staple 

#verify the ocsp stapling file
verifyResult=`openssl ocsp -no_nonce -issuer baidu_issuer.crt -CAfile CAbundle.crt -cert baidu.crt -respin ./output/domain.staple 2>&1 | grep 'Response verify OK'`
status=`openssl ocsp -no_nonce -issuer baidu_issuer.crt -CAfile CAbundle.crt -cert baidu.crt -respin ./output/domain.staple | grep 'baidu.crt: good'`
if [ -n "$verifyResult" ] && [ -n "$status" ]
then
    cp -r output ../
    cd ../output && md5sum domain.staple >domain.staple.md5
fi

# @Author   : xiansong wu
# @Time     : 2022/1/14 17:58
# @Function :

from rest_framework import serializers


class LoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True,
                                     allow_null=False,
                                     )
    password = serializers.CharField(required=True,
                                     allow_null=False,
                                     )
    eauth = serializers.CharField(required=True,
                                  allow_null=False,
                                  )


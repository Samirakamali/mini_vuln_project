from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import get_user_model
from rest_framework import serializers
from .models import ActivityLog

User = get_user_model() #get every user model from setting. we define this like this to not be depend to a spesifc model name


class RegisterSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True, min_length=6)

    class Meta:
        model = User # this means this serializer work on this model
        fields = [
            "id", "username", "password", "email",
            "first_name", "last_name", "phone", "organization"
        ] # recive these fields from request and validate and save them

    def create(self, validated_data): # this is executed when serializer.save() is called
        password = validated_data.pop("password")
        user = User(**validated_data) # makain an user without password: user = CustomUser(username="samira", email="samira@uni-oulu.fi")
        user.set_password(password) # hash the password
        user.save()
        return user

class MeSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["id", "username", "email", "first_name", "last_name"]
        

class ActivityLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = ActivityLog
        fields = ["id", "action", "ip", "user_agent", "extra", "created_at"]


class ProfileUpdateSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "phone", "organization"] # an user could only update these fields
        extra_kwargs = {
            "email": {"required": False},
            "first_name": {"required": False},
            "last_name": {"required": False},
            "phone": {"required": False},
            "organization": {"required": False},
        } #non of these fields are not required.

    def validate_email(self, value):
        user = self.context["request"].user
        if User.objects.filter(email__iexact=value).exclude(id=user.id).exists():
            raise serializers.ValidationError("Email already in use.")
        return value

class ChangePasswordSerializer(serializers.Serializer):
    old_password = serializers.CharField(write_only=True)
    new_password = serializers.CharField(write_only=True) #write_only=True:password is not retrurened in response.

    def validate_new_password(self, value):
        validate_password(value) #password validation
        return value

class ForgotPasswordRequestSerializer(serializers.Serializer):
    email = serializers.EmailField()



class ForgotPasswordConfirmSerializer(serializers.Serializer):
    uid = serializers.CharField()
    token = serializers.CharField()
    new_password = serializers.CharField(write_only=True)

    def validate_new_password(self, value):
        validate_password(value)
        return value
    

class DeleteAccountSerializer(serializers.Serializer):
    password = serializers.CharField(write_only=True)

    def validate_password(self, value):
        user = self.context["request"].user
        if not user.check_password(value):
            raise serializers.ValidationError("Password is incorrect.")
        return value

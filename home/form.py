from dataclasses import field
from pyexpat import model
from django.forms import ModelForm
from django import forms
from django.contrib.auth.forms import UserCreationForm, PasswordChangeForm
from django.contrib.auth.models import User
from django.core.exceptions import ValidationError
from .models import *


class CreateUserForm(UserCreationForm):
    class Meta:
        model = User
        fields = ['username','password1', 'password2']
    def clean(self):
       email = self.cleaned_data.get('email')
       if User.objects.filter(email=email).exists():
            raise ValidationError("Email exists")
       return self.cleaned_data
class FormInfo(ModelForm):
    class Meta:
        model = Account_info
        fields = ['name','email','phone','birth','address']
        widgets = {
            'birth': forms.DateInput()
        }
class ChangePasswordForm(PasswordChangeForm):
    class Meta:
        model = User
        fields = ['old_password', 'new_password1', 'new_password2']
class UploadFileForm(ModelForm):
    class Meta:
        model = Encrypt
        fields = ['receiver_email','file']
class DecryptForm(ModelForm):
    class Meta:
        model = Encrypt
        fields = ['file']

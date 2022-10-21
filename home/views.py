import RSA
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from xml.etree.ElementTree import Comment
from django.shortcuts import render, redirect 
from django.contrib import messages
from home.form import *
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.db import IntegrityError
from .decorators import *
from .encrypt import *
from .models import *
# Create your views here.
def home(request):
    return render(request,'pages/home.html')
@unauthenticated_user
def loginPage(request):
    if request.method == 'POST':

        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)

        if email == '':
            messages.error(request, 'Tên đăng nhập không được để trống')

        elif password == '' : 
            messages.error(request, 'Mật khẩu không được bỏ trống')
        elif user is not None:
            login(request, user)
            return redirect('complete_info')
        else: 
            messages.error(request, 'Tên đăng nhập hoặc mật khẩu chưa đúng.')
    return render(request,'pages/login.html')
@login_required(login_url='login')
def logoutUser(request):
    logout(request)
    return redirect('home')
@unauthenticated_user
def register(request):
    form = CreateUserForm()
    if request.method == 'POST':
        form = CreateUserForm(request.POST)
        if form.is_valid(): 
            user = form.save()
            username = form.cleaned_data.get('username')
            return redirect('loginPage')

    return render(request,'pages/register.html',{'form':form})

def complete_info(request):
    
    if request.user.is_authenticated:
        username = request.user.username
    is_ex = User.objects.filter(username=username).exists()
    if is_ex is True:
        user = User.objects.get(username=username)
    if Account_info.objects.filter(user = user).exists() == True:
        return redirect('home')
    form = FormInfo()
    if request.method == 'POST':
        form = FormInfo(request.POST)
        form.user = user
    if form.is_valid():
        try:
            Info = form.save()
        except Exception as e:
            messages.error(request, e)
            return redirect('complete_info')
        if is_ex is True:
            user = User.objects.get(username=username)
            Info.user = user
            key = RSA.generate(2048)
            passphase = user.password
            cipherkey, tag, nonce = encrypt_rsa(passphase,key.export_key())
            Info.public_key = nonce + tag + cipherkey
            Info.public_key1 = nonce + tag + cipherkey
            print(Info.public_key1)
            Info.private_key =  key.public_key().export_key()
        try: 
            Info.save()
        except IntegrityError:
            messages.error(request, 'Đã có  "' + user.username + '"')
            Info.delete()
            return redirect('home')
        return redirect('home')

    form = FormInfo()
    if request.method == 'POST':
        form = FormInfo(request.POST)
        if form.is_valid():
            Acc = form.save()
            username = form.cleaned_data.get('username')
            return redirect('login')
    return render(request,'pages/complete_info.html',{'form':form})

def edit_info(request):
    return render(request,'pages/change_password.html')

@login_required(login_url='login')
def account_setting(request):
    if request.user.is_authenticated:
        username = request.user.username
    is_ex = User.objects.filter(username=username).exists()
    if is_ex is True:
        user = User.objects.get(username=username)
    if Account_info.objects.filter(user = user).exists() == True:
        acc = Account_info.objects.get(user = user)
    form = FormInfo(instance=acc)

    if request.method == 'POST':
        form = FormInfo(request.POST, request.FILES,instance=acc)

        if form.is_valid():
            form.save()
            messages.success(request,'Thay đổi thông tin thành công')
            return redirect('account_setting')
    return render(request,'pages/account_setting.html',{'form':form})

@login_required(login_url='login')
def password_change(request):
    form = ChangePasswordForm(request.user)

    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)

        if form.is_valid():
            user = form.save()
            update_session_auth_hash(request, user)
            messages.success(request, 'Đổi mật khẩu thành công!')
            return redirect('password_change_done')

    context = {'form':form}
    return render(request, 'pages/change_password.html', context)
def password_change_done(request):
    context = {}
    return render(request, 'pages/password_change_done.html', context)

def upload (request):
    if request.user.is_authenticated:
        username = request.user.username
    is_ex = User.objects.filter(username=username).exists()
    if is_ex is True:
        user = User.objects.get(username=username)
    if Account_info.objects.filter(user = user).exists() == True:
        acc = Account_info.objects.get(user = user)
    form = UploadFileForm()
    if request.method == 'POST':
        try:
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                print('y')
                file = form.save()
                file_name = file.file
                en_file_name = form.cleaned_data.get('name')
                print(en_file_name)
                print(acc.public_key1)
                file.en_file = encrypt_file(acc.public_key1,file_name,en_file_name)
                file.save() 
            return redirect('en_success')
        except Exception as e:
            messages.error(request, e)
            return redirect('upload_file')
    context = {'form':form}
    return render(request, 'pages/encrypt/upload.html', context)

def en_success(request):

    return render(request, 'pages/encrypt/encrypt_success.html')

def InputEmailPage(request):
    form = SendFile()
    if request.method == 'POST':
        print('pot')
        form = SendFile(request.POST)
        if form.is_valid():
            email =  form.cleaned_data.get('email')
            print(email)
            return redirect('home')
    context = {'form':form}
    return render(request, 'pages/encrypt/InputEmail.html', context)
 
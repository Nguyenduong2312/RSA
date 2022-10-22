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
            password = form.cleaned_data.get('password2')
            print(password)
            return redirect('loginPage')

    return render(request,'pages/register.html',{'form':form})

def complete_info(request):
    user = request.user    
    if Account_info.objects.filter(user = user).exists() == True:
        return redirect('home')
    form = FormInfo()
    if request.method == 'POST':
        password = request.POST['pwd']
        verify_user = authenticate(request, username=user.username, password=password)

        if verify_user == None:
            print('sai')
            messages.error(request,'Password cũ không đúng')
            return redirect('complete_info')
        form = FormInfo(request.POST)
        form.user = user
    if form.is_valid():
        try:
            Info = form.save()
        except Exception as e:
            messages.error(request, e)
            return redirect('complete_info')

        Info.user = user
        key = RSA.generate(2048)
        passphrase = password#
        print("aa",passphrase)
        cipherkey, tag, nonce = encrypt_rsa(passphrase,key.export_key())
        Info.public_key = key.public_key().export_key()
        print(Info.public_key)
        Info.private_key =  nonce + tag + cipherkey
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
    if request.user.is_authenticated:
        username = request.user.username
    is_ex = User.objects.filter(username=username).exists()
    if is_ex is True:
        user = User.objects.get(username=username)
    if Account_info.objects.filter(user = user).exists() == True:
        acc = Account_info.objects.get(user = user)
    form = ChangePasswordForm(request.user)

    if request.method == 'POST':
        form = ChangePasswordForm(request.user, request.POST)
        
        if form.is_valid():
            user = form.save()
            new_password = form.cleaned_data['new_password2']
            update_session_auth_hash(request, user) 
            messages.success(request, 'Đổi mật khẩu thành công!')
            return redirect('password_change_done')

    context = {'form':form}
    return render(request, 'pages/change_password.html', context)
def password_change_done(request):
    context = {}
    return render(request, 'pages/password_change_done.html', context)

def upload (request):
    user = request.user
    if Account_info.objects.filter(user = user).exists() == True:
        acc_user = Account_info.objects.get(user = user)
        print(acc_user.email)
    form = UploadFileForm()
    if request.method == 'POST':
        try:
            form = UploadFileForm(request.POST, request.FILES)
            if form.is_valid():
                print("yy")
                email = request.POST['receiver_email']
                if Account_info.objects.filter(email = email).exists() == True:
                    acc = Account_info.objects.get(email = email)
                file = form.save()
                file.sender_email = acc_user.email
                file_name = file.file.path
                print(file_name)
                en_file_name = "en_" +str(file.file)[:-4]
                file.en_file = encrypt_file(acc.public_key,file_name,en_file_name)
                file.save() 
                return redirect('en_success')
        except Exception as e:
            messages.error(request, e)
            return redirect('upload_file')
    context = {'form':form}
    return render(request, 'pages/encrypt/upload.html', context)

def en_success(request):
    return render(request, 'pages/encrypt/encrypt_success.html')
 
def en_list(request):
    context = {}
    if request.user.is_authenticated:
        username = request.user.username
    is_ex = User.objects.filter(username=username).exists()
    if is_ex is True:
        user = User.objects.get(username=username)
    if Account_info.objects.filter(user = user).exists() == True:
        acc_user = Account_info.objects.get(user = user)
        email = acc_user.email
        print("a",email)
        list = Encrypt.objects.filter(sender_email = email)
        path = list[0].file.path
        print(path)
        context = {'list':list,'link':path}
    return render(request, 'pages/encrypt/en_list.html',context)


def decrypt(request):
    print('a')
    user = request.user
    if Account_info.objects.filter(user = user).exists() == True:
        acc_user = Account_info.objects.get(user = user)
    form = DecryptForm()

    if request.method == 'POST':
        try: 
            form = DecryptForm(request.POST, request.FILES)
            if form.is_valid():

                password = request.POST['pwd']
                verify_user = authenticate(request, username=user.username, password=password)
                print(password)
                if verify_user == None:
                    print('sai')
                    messages.error(request,'Password cũ không đúng')
                    return redirect('decrypt')
        except Exception as e:
            messages.error(request, e)
            return redirect('decrypt')

    #print(acc_user.private_key,"---",user.password)
    cipherkey, tag, nonce = acc_user.private_key[0:16], acc_user.private_key[16:32], acc_user.private_key[32:]
    #print(cipherkey,"---",tag)
    key_decrypt = decrypt_rsa_private_key(password, cipherkey, tag, nonce)
    #decrypt_file('media/en.bin',key_decrypt)
    context = {'form':form}

    return render(request, 'pages/encrypt/decrypt.html',context)

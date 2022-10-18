from django.urls import path
from django.conf.urls.static import static
from django.conf import settings
from . import views

urlpatterns = [
    path('', views.home,name='home'),   
    path('loginPage/', views.loginPage,name='loginPage'),   
    path('logout/', views.logoutUser, name='logout'),
    path('register/', views.register,name='register'),   
    path('complete_info/', views.complete_info,name='complete_info'),   
    path('account_setting/', views.account_setting,name='account_setting'),   
    
    path('change_password/', views.password_change,name='change_password'),   
    path('password_change_done/', views.password_change_done,name='password_change_done'),   

    path('upload_file/', views.upload,name='upload_file'),   
    path('en_success/', views.en_success,name='en_success'),   
    path('InputEmailPage/', views.InputEmailPage,name='InputEmailPage'),   

]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
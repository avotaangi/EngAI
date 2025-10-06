# users/urls.py
from django.urls import path
from .views import (
    registration_view, 
    login_view, 
    logout_view, 
    change_password_view, 
    index_view, 
    profile_view,
    sms_verification_view,
    friends_view,
    search_friends,
    send_friend_request,
    respond_friend_request,
    remove_friend,
    messages_view,
    chat_view,
    send_message,
    upload_file,
    get_messages
)
from django.views.generic import TemplateView

urlpatterns = [
    path('', login_view, name='index'),
    path('register/', registration_view, name='register'),
    path('sms-verification/', sms_verification_view, name='sms_verification'),
    path('login/', login_view, name='login'),
    path('accounts/login/', login_view, name='accounts_login'),
    path('logout/', logout_view, name='logout'),
    path('password-reset/', change_password_view, name='password_reset'),
    path('home/', index_view, name='home'),
    path('profile/', profile_view, name='profile'),
    path('friends/', friends_view, name='friends'),
    path('friends/search/', search_friends, name='search_friends'),
    path('friends/send-request/', send_friend_request, name='send_friend_request'),
    path('friends/respond/', respond_friend_request, name='respond_friend_request'),
    path('friends/remove/', remove_friend, name='remove_friend'),
    
    # Маршруты для системы сообщений
    path('messages/', messages_view, name='messages'),
    path('chat/<int:user_id>/', chat_view, name='chat'),
    path('chat/send-message/', send_message, name='send_message'),
    path('chat/upload-file/', upload_file, name='upload_file'),
    path('chat/<int:chat_id>/get-messages/', get_messages, name='get_messages'),
    path('test/', TemplateView.as_view(template_name='users/test.html'), name='test'),
]

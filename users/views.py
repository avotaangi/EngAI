from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout, get_user_model
from django.contrib.auth.decorators import login_required
from .forms import RegistrationForm, PasswordChangeForm, ProfileEditForm
from .utils import log_user_action, generate_sms_code, send_sms_code
from django.core.exceptions import ValidationError
from .models import User, Friendship, Chat, Message
from django.core.mail import send_mail
import random
from django.http import JsonResponse
from django.views.decorators.http import require_POST
from django.db.models import Q
from django.core.paginator import Paginator

def index_view(request):
    if not request.user.is_authenticated:
        return redirect('login')
    return render(request, 'users/index.html')

def registration_view(request):
    if request.user.is_authenticated:
        return redirect('index')
        
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        
        # Проверка согласия на обработку персональных данных
        if not request.POST.get('personal_data_agreement'):
            messages.error(request, 'Необходимо согласиться с обработкой персональных данных')
            return render(request, 'users/registration.html', {'form': form})
        
        if form.is_valid():
            try:
                # Проверка уникальности email
                User = get_user_model()
                if User.objects.filter(email=form.cleaned_data['email']).exists():
                    messages.error(request, 'Пользователь с таким email уже существует')
                    return render(request, 'users/registration.html', {'form': form})
                
                # Создание пользователя
                user = form.save(commit=False)
                user.is_active = True  # Пользователь активен сразу
                user.save()
                
                # Авторизуем пользователя с указанием бэкенда
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                
                # Логируем действие
                log_user_action(user, 'register', request)
                
                messages.success(request, 'Регистрация успешно завершена!')
                return redirect('index')
            
            except ValidationError as e:
                messages.error(request, str(e))
                return render(request, 'users/registration.html', {'form': form})
    else:
        form = RegistrationForm()
    
    return render(request, 'users/registration.html', {'form': form})

def sms_verification_view(request):
    if request.method == 'POST':
        sms_code = request.session.get('registration_sms_code')
        user_id = request.session.get('registration_user_id')
        
        if not sms_code or not user_id:
            messages.error(request, 'Истекло время ожидания. Пройдите регистрацию заново.')
            return redirect('register')
        
        User = get_user_model()
        try:
            user = User.objects.get(id=user_id)
            entered_code = request.POST.get('sms_code')
            
            if entered_code == sms_code:
                user.is_active = True
                user.save()
                
                # Очистка сессии
                del request.session['registration_sms_code']
                del request.session['registration_user_id']
                
                messages.success(request, 'Регистрация успешно завершена! Теперь вы можете войти.')
                return redirect('login')
            else:
                messages.error(request, 'Неверный код подтверждения')
        except User.DoesNotExist:
            messages.error(request, 'Пользователь не найден')
    
    return render(request, 'users/sms_verification.html')

def login_view(request):
    if request.user.is_authenticated:
        return redirect('/home/')
    
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')
        user = authenticate(request, username=email, password=password)
        
        if user is not None:
            login(request, user)
            log_user_action(user, 'login', request)
            return redirect('/home/')
        else:
            messages.error(request, 'Неверный email или пароль')
    
    return render(request, 'users/login.html')

def logout_view(request):
    if request.user.is_authenticated:
        log_user_action(request.user, 'logout', request)
    logout(request)
    return redirect('login')

@login_required
def profile_view(request):
    if request.method == 'POST':
        form = ProfileEditForm(request.POST, instance=request.user)
        if form.is_valid():
            form.save()
            log_user_action(request.user, 'profile_update', request)
            messages.success(request, 'Профиль успешно обновлен!')
            return redirect('profile')
        # Не добавляем общее сообщение об ошибке, ошибки отображаются рядом с полями
    else:
        form = ProfileEditForm(instance=request.user)
    
    return render(request, 'users/profile.html', {'form': form})

def change_password_view(request):
    if request.user.is_authenticated:
        # Для авторизованных пользователей - изменение пароля
        if request.method == 'POST':
            form = PasswordChangeForm(request.POST)
            if form.is_valid():
                user = request.user
                user.set_password(form.cleaned_data['password1'])
                user.save()
                log_user_action(user, 'password_change', request)
                messages.success(request, 'Пароль успешно изменен!')
                return redirect('login')
        else:
            form = PasswordChangeForm()
        
        return render(request, 'users/change_password.html', {'form': form})
    else:
        # Для неавторизованных пользователей - сброс пароля по email
        if request.method == 'POST':
            email = request.POST.get('email')
            User = get_user_model()
            try:
                user = User.objects.get(email=email)
                # Здесь в реальном приложении отправлялся бы email со ссылкой для сброса
                log_user_action(user, 'password_reset', request)
                messages.success(request, 'Инструкции по сбросу пароля отправлены на ваш email.')
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, 'Пользователь с таким email не найден.')
        
        return render(request, 'users/password_reset.html')

def register(request):
    if request.method == 'POST':
        # Получаем данные из формы
        email = request.POST.get('email')
        password1 = request.POST.get('password1')
        password2 = request.POST.get('password2')
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        phone_number = request.POST.get('phone_number')
        verification_code = request.POST.get('verification_code')

        # Проверяем, существует ли пользователь
        if User.objects.filter(email=email).exists():
            messages.error(request, 'Пользователь с таким email уже существует')
            return render(request, 'users/registration.html')

        # Проверяем совпадение паролей
        if password1 != password2:
            messages.error(request, 'Пароли не совпадают')
            return render(request, 'users/registration.html')

        # Если это первый шаг (email и пароль)
        if email and password1 and not first_name:
            # Генерируем код подтверждения
            code = str(random.randint(100000, 999999))
            request.session['verification_code'] = code
            request.session['email'] = email
            request.session['password'] = password1

            # Отправляем код на email
            send_mail(
                'Код подтверждения',
                f'Ваш код подтверждения: {code}',
                'from@example.com',
                [email],
                fail_silently=False,
            )
            return render(request, 'users/registration.html')

        # Если это второй шаг (личные данные)
        elif first_name and last_name and phone_number:
            request.session['first_name'] = first_name
            request.session['last_name'] = last_name
            request.session['phone_number'] = phone_number
            return render(request, 'users/registration.html')

        # Если это третий шаг (подтверждение)
        elif verification_code:
            stored_code = request.session.get('verification_code')
            if verification_code == stored_code:
                # Создаем пользователя
                user = User.objects.create_user(
                    email=request.session.get('email'),
                    password=request.session.get('password'),
                    first_name=request.session.get('first_name'),
                    last_name=request.session.get('last_name'),
                    phone_number=request.session.get('phone_number')
                )
                
                # Очищаем сессию
                for key in ['verification_code', 'email', 'password', 'first_name', 'last_name', 'phone_number']:
                    request.session.pop(key, None)
                
                # Авторизуем пользователя с указанием бэкенда
                login(request, user, backend='django.contrib.auth.backends.ModelBackend')
                return redirect('home')
            else:
                messages.error(request, 'Неверный код подтверждения')
                return render(request, 'users/registration.html')

    return render(request, 'users/registration.html')

@require_POST
def resend_code(request):
    email = request.session.get('email')
    if email:
        # Генерируем новый код
        code = str(random.randint(100000, 999999))
        request.session['verification_code'] = code

        # Отправляем код на email
        send_mail(
            'Код подтверждения',
            f'Ваш код подтверждения: {code}',
            'from@example.com',
            [email],
            fail_silently=False,
        )
        return JsonResponse({'success': True})
    return JsonResponse({'success': False})


@login_required
def friends_view(request):
    """Основная страница друзей"""
    friends = Friendship.get_friends(request.user)
    pending_requests = Friendship.get_pending_requests(request.user)
    
    context = {
        'friends': friends,
        'pending_requests': pending_requests,
        'active_tab': request.GET.get('tab', 'friends')  # friends, search, requests
    }
    return render(request, 'users/friends.html', context)


@login_required
def search_friends(request):
    """Поиск пользователей для добавления в друзья"""
    query = request.GET.get('q', '').strip()
    results = []
    
    if query and len(query) >= 2:
        # Поиск по имени, фамилии и email
        users = User.objects.filter(
            Q(first_name__icontains=query) |
            Q(last_name__icontains=query) |
            Q(email__icontains=query)
        ).exclude(id=request.user.id)[:20]  # Ограничиваем 20 результатами
        
        for user in users:
            # Проверяем статус отношений
            is_friend = Friendship.are_friends(request.user, user)
            
            # Проверяем, есть ли отправленная заявка
            pending_request = Friendship.objects.filter(
                Q(from_user=request.user, to_user=user) | 
                Q(from_user=user, to_user=request.user),
                status='pending'
            ).first()
            
            status = 'none'
            if is_friend:
                status = 'friend'
            elif pending_request:
                if pending_request.from_user == request.user:
                    status = 'sent'
                else:
                    status = 'received'
            
            results.append({
                'id': user.id,
                'name': user.get_full_name() or user.email,
                'email': user.email,
                'level': user.get_current_language_level_display(),
                'level_code': user.current_language_level,
                'status': status
            })
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({'results': results})
    
    return render(request, 'users/friends.html', {
        'search_results': results,
        'search_query': query,
        'active_tab': 'search',
        'friends': Friendship.get_friends(request.user),
        'pending_requests': Friendship.get_pending_requests(request.user),
    })


@login_required
@require_POST
def send_friend_request(request):
    """Отправка заявки в друзья"""
    user_id = request.POST.get('user_id')
    
    try:
        to_user = User.objects.get(id=user_id)
        friendship, message = Friendship.send_friend_request(request.user, to_user)
        
        return JsonResponse({
            'success': friendship is not None,
            'message': message
        })
    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Пользователь не найден'
        })


@login_required
@require_POST 
def respond_friend_request(request):
    """Ответ на заявку в друзья"""
    request_id = request.POST.get('request_id')
    action = request.POST.get('action')  # 'accept' или 'decline'
    
    try:
        friendship = Friendship.objects.get(
            id=request_id,
            to_user=request.user,
            status='pending'
        )
        
        if action == 'accept':
            friendship.status = 'accepted'
            message = f'Вы теперь друзья с {friendship.from_user.get_full_name()}!'
        elif action == 'decline':
            friendship.status = 'declined'
            message = 'Заявка отклонена'
        else:
            return JsonResponse({
                'success': False,
                'message': 'Неверное действие'
            })
        
        friendship.save()
        
        return JsonResponse({
            'success': True,
            'message': message
        })
        
    except Friendship.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Заявка не найдена'
        })


@login_required
@require_POST
def remove_friend(request):
    """Удаление из друзей"""
    friend_id = request.POST.get('friend_id')
    
    try:
        friend = User.objects.get(id=friend_id)
        
        # Находим связь дружбы
        friendship = Friendship.objects.filter(
            Q(from_user=request.user, to_user=friend) |
            Q(from_user=friend, to_user=request.user),
            status='accepted'
        ).first()
        
        if friendship:
            friendship.delete()
            return JsonResponse({
                'success': True,
                'message': f'{friend.get_full_name()} удален из друзей'
            })
        else:
            return JsonResponse({
                'success': False,
                'message': 'Дружба не найдена'
            })
            
    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Пользователь не найден'
        })


@login_required
def messages_view(request):
    """Страница со списком чатов"""
    # Получаем все чаты пользователя
    user_chats = Chat.objects.filter(
        Q(user1=request.user) | Q(user2=request.user)
    ).prefetch_related('messages').order_by('-updated_at')
    
    # Подготавливаем данные для шаблона
    chats_data = []
    for chat in user_chats:
        other_user = chat.get_other_user(request.user)
        last_message = chat.get_last_message()
        unread_count = chat.get_unread_count(request.user)
        
        chats_data.append({
            'chat': chat,
            'other_user': other_user,
            'last_message': last_message,
            'unread_count': unread_count,
        })
    
    # Поиск по чатам
    search_query = request.GET.get('q', '')
    if search_query:
        chats_data = [chat_data for chat_data in chats_data 
                     if search_query.lower() in (chat_data['other_user'].get_full_name() or chat_data['other_user'].email).lower()]
    
    return render(request, 'users/messages.html', {
        'chats_data': chats_data,
        'search_query': search_query,
    })


@login_required
def chat_view(request, user_id):
    """Страница чата с конкретным пользователем"""
    other_user = get_object_or_404(User, id=user_id)
    
    # Проверяем, что пользователи друзья (информационная безопасность)
    if not Friendship.are_friends(request.user, other_user):
        messages.error(request, 'Вы можете обмениваться сообщениями только с друзьями')
        return redirect('friends')
    
    # Получаем или создаем чат
    chat = Chat.get_or_create_chat(request.user, other_user)
    
    # Отмечаем сообщения как прочитанные
    chat.messages.filter(is_read=False).exclude(sender=request.user).update(is_read=True)
    
    # Получаем сообщения с пагинацией
    messages_list = chat.messages.order_by('-created_at')
    paginator = Paginator(messages_list, 50)  # 50 сообщений на страницу
    
    page_number = request.GET.get('page')
    messages_page = paginator.get_page(page_number)
    
    # Обращаем порядок для отображения (сообщения сверху вниз)
    messages_page.object_list = list(reversed(messages_page.object_list))
    
    return render(request, 'users/chat.html', {
        'chat': chat,
        'other_user': other_user,
        'messages': messages_page,
    })


@login_required
@require_POST
def send_message(request):
    """Отправка сообщения"""
    chat_id = request.POST.get('chat_id')
    content = request.POST.get('content', '').strip()
    
    if not content:
        return JsonResponse({
            'success': False,
            'message': 'Сообщение не может быть пустым'
        })
    
    try:
        chat = Chat.objects.get(id=chat_id)
        
        # Проверяем, что пользователь участвует в чате
        if request.user not in [chat.user1, chat.user2]:
            return JsonResponse({
                'success': False,
                'message': 'Нет доступа к этому чату'
            })
        
        # Создаем сообщение
        message = Message.objects.create(
            chat=chat,
            sender=request.user,
            content=content,
            message_type='text'
        )
        
        return JsonResponse({
            'success': True,
            'message': {
                'id': message.id,
                'content': message.content,
                'sender_name': message.sender.get_full_name() or message.sender.email,
                'sender_id': message.sender.id,
                'created_at': message.created_at.strftime('%d.%m.%Y %H:%M'),
                'message_type': message.message_type,
            }
        })
        
    except Chat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Чат не найден'
        })


@login_required
@require_POST
def upload_file(request):
    """Загрузка файла в чат"""
    from .file_validators import validate_chat_file, FileValidator
    from django.core.exceptions import ValidationError
    
    chat_id = request.POST.get('chat_id')
    uploaded_file = request.FILES.get('file')
    
    if not uploaded_file:
        return JsonResponse({
            'success': False,
            'message': 'Файл не выбран'
        })
    
    # Валидация файла с помощью безопасного валидатора
    try:
        validate_chat_file(uploaded_file)
    except ValidationError as e:
        return JsonResponse({
            'success': False,
            'message': ', '.join(e.messages)
        })
    
    # Очистка имени файла
    uploaded_file.name = FileValidator.sanitize_filename(uploaded_file.name)
    
    try:
        chat = Chat.objects.get(id=chat_id)
        
        # Проверяем, что пользователь участвует в чате
        if request.user not in [chat.user1, chat.user2]:
            return JsonResponse({
                'success': False,
                'message': 'Нет доступа к этому чату'
            })
        
        # Создаем сообщение с файлом
        message = Message.objects.create(
            chat=chat,
            sender=request.user,
            file=uploaded_file,
            file_name=uploaded_file.name,
            file_size=uploaded_file.size
        )
        
        return JsonResponse({
            'success': True,
            'message': {
                'id': message.id,
                'sender_name': message.sender.get_full_name() or message.sender.email,
                'sender_id': message.sender.id,
                'created_at': message.created_at.strftime('%d.%m.%Y %H:%M'),
                'message_type': message.message_type,
                'file_name': message.file_name,
                'file_size': message.file_size_human,
                'file_url': message.file.url if message.file else None,
                'is_image': message.is_image,
            }
        })
        
    except Chat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Чат не найден'
        })


@login_required
def get_messages(request, chat_id):
    """Получение новых сообщений для AJAX"""
    try:
        chat = Chat.objects.get(id=chat_id)
        
        # Проверяем, что пользователь участвует в чате
        if request.user not in [chat.user1, chat.user2]:
            return JsonResponse({
                'success': False,
                'message': 'Нет доступа к этому чату'
            })
        
        # Получаем ID последнего сообщения
        last_message_id = request.GET.get('last_message_id', 0)
        
        # Получаем новые сообщения
        new_messages = chat.messages.filter(
            id__gt=last_message_id
        ).order_by('created_at')
        
        # Отмечаем как прочитанные
        new_messages.exclude(sender=request.user).update(is_read=True)
        
        messages_data = []
        for message in new_messages:
            message_data = {
                'id': message.id,
                'sender_name': message.sender.get_full_name() or message.sender.email,
                'sender_id': message.sender.id,
                'created_at': message.created_at.strftime('%d.%m.%Y %H:%M'),
                'message_type': message.message_type,
            }
            
            if message.message_type == 'text':
                message_data['content'] = message.content
            else:
                message_data['file_name'] = message.file_name
                message_data['file_size'] = message.file_size_human
                message_data['file_url'] = message.file.url if message.file else None
                message_data['is_image'] = message.is_image
            
            messages_data.append(message_data)
        
        return JsonResponse({
            'success': True,
            'messages': messages_data
        })
        
    except Chat.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'Чат не найден'
        })

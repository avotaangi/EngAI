from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.utils.translation import gettext_lazy as _
from django.utils import timezone
from datetime import timedelta


class UserManager(BaseUserManager):
    def _create_user(self, email, password, **extra_fields):
        if not email:
            raise ValueError('Email должен быть указан')
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(email, password, **extra_fields)

    def create_superuser(self, email, password, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        return self._create_user(email, password, **extra_fields)


class User(AbstractUser):
    username = None
    email = models.EmailField('Email', unique=True)

    # Дополнительные поля
    birth_date = models.DateField('Дата рождения', null=True, blank=True)
    current_language_level = models.CharField(
        'Текущий уровень языка',
        max_length=2,
        choices=[('A1', 'A1'), ('A2', 'A2'), ('B1', 'B1'),
                 ('B2', 'B2'), ('C1', 'C1'), ('C2', 'C2')],
        default='A1'
    )
    desired_language_level = models.CharField(
        'Желаемый уровень языка',
        max_length=2,
        choices=[('A1', 'A1'), ('A2', 'A2'), ('B1', 'B1'),
                 ('B2', 'B2'), ('C1', 'C1'), ('C2', 'C2')],
        default='A2'
    )
    user_role = models.CharField(
        'Роль пользователя',
        max_length=20,
        choices=[
            ('student', 'Ученик'),
            ('teacher', 'Преподаватель'),
        ],
        default='student'
    )
    phone_number = models.CharField('Номер телефона', max_length=20, blank=True)
    city = models.CharField('Город проживания', max_length=100, blank=True)
    profile_completed = models.BooleanField('Профиль завершен', default=False)

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    def __str__(self):
        return self.email
    
    def is_profile_complete(self):
        """Проверяет, заполнен ли профиль пользователя"""
        # Сначала проверяем флаг, затем поля
        if self.profile_completed:
            return True
            
        # Если флаг не установлен, проверяем поля
        fields_complete = (
            self.first_name and 
            self.last_name and 
            self.city and 
            self.current_language_level and 
            self.desired_language_level
        )
        
        # Если поля заполнены, автоматически обновляем флаг
        if fields_complete and not self.profile_completed:
            self.profile_completed = True
            self.save()
            
        return fields_complete
    
    def get_display_name(self):
        """Получает отображаемое имя пользователя"""
        if self.first_name and self.last_name:
            return f"{self.first_name} {self.last_name}"
        elif self.first_name:
            return self.first_name
        elif self.last_name:
            return self.last_name
        else:
            return self.email.split('@')[0]  # Используем часть email до @


class UserLog(models.Model):
    ACTION_CHOICES = [
        ('login', 'Вход в систему'),
        ('logout', 'Выход из системы'),
        ('register', 'Регистрация'),
        ('password_reset', 'Сброс пароля'),
        ('password_change', 'Изменение пароля'),
        ('profile_update', 'Обновление профиля'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='logs')
    action = models.CharField(max_length=20, choices=ACTION_CHOICES)
    timestamp = models.DateTimeField(default=timezone.now)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(null=True, blank=True)
    details = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = 'Лог пользователя'
        verbose_name_plural = 'Логи пользователей'

    def __str__(self):
        return f"{self.user.email} - {self.get_action_display()} - {self.timestamp}"


class Friendship(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Ожидает подтверждения'),
        ('accepted', 'Принято'),
        ('declined', 'Отклонено'),
    ]
    
    from_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_friend_requests')
    to_user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='received_friend_requests')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    created_at = models.DateTimeField(default=timezone.now)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('from_user', 'to_user')
        verbose_name = 'Дружба'
        verbose_name_plural = 'Дружбы'
    
    def __str__(self):
        return f"{self.from_user.get_full_name()} -> {self.to_user.get_full_name()} ({self.get_status_display()})"
    
    @classmethod
    def are_friends(cls, user1, user2):
        """Проверяет, являются ли пользователи друзьями"""
        return cls.objects.filter(
            models.Q(from_user=user1, to_user=user2) | models.Q(from_user=user2, to_user=user1),
            status='accepted'
        ).exists()
    
    @classmethod
    def get_friends(cls, user):
        """Получает всех друзей пользователя"""
        friends_from = cls.objects.filter(from_user=user, status='accepted').values_list('to_user', flat=True)
        friends_to = cls.objects.filter(to_user=user, status='accepted').values_list('from_user', flat=True)
        friend_ids = list(friends_from) + list(friends_to)
        return User.objects.filter(id__in=friend_ids)
    
    @classmethod
    def get_pending_requests(cls, user):
        """Получает заявки в друзья для пользователя"""
        return cls.objects.filter(to_user=user, status='pending')
    
    @classmethod 
    def send_friend_request(cls, from_user, to_user):
        """Отправляет заявку в друзья"""
        if from_user == to_user:
            return None, 'Нельзя отправить заявку самому себе'
        
        if cls.are_friends(from_user, to_user):
            return None, 'Вы уже друзья'
        
        existing = cls.objects.filter(
            models.Q(from_user=from_user, to_user=to_user) | 
            models.Q(from_user=to_user, to_user=from_user)
        ).first()
        
        if existing:
            if existing.status == 'pending':
                return None, 'Заявка уже отправлена'
            elif existing.status == 'declined':
                existing.status = 'pending'
                existing.from_user = from_user
                existing.to_user = to_user
                existing.save()
                return existing, 'Заявка отправлена повторно'
        
        friendship = cls.objects.create(from_user=from_user, to_user=to_user)
        return friendship, 'Заявка в друзья отправлена'


class Chat(models.Model):
    """Модель для чата между двумя пользователями"""
    user1 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chats_as_user1')
    user2 = models.ForeignKey(User, on_delete=models.CASCADE, related_name='chats_as_user2')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ['user1', 'user2']
        ordering = ['-updated_at']
        verbose_name = 'Чат'
        verbose_name_plural = 'Чаты'
    
    @classmethod
    def get_or_create_chat(cls, user1, user2):
        """Получить или создать чат между двумя пользователями"""
        # Упорядочиваем пользователей по ID, чтобы избежать дубликатов
        if user1.id > user2.id:
            user1, user2 = user2, user1
        
        chat, created = cls.objects.get_or_create(user1=user1, user2=user2)
        return chat
    
    def get_other_user(self, current_user):
        """Получить другого участника чата"""
        return self.user2 if self.user1 == current_user else self.user1
    
    def get_last_message(self):
        """Получить последнее сообщение"""
        return self.messages.order_by('-created_at').first()
    
    def get_unread_count(self, user):
        """Получить количество непрочитанных сообщений"""
        return self.messages.filter(
            is_read=False
        ).exclude(sender=user).count()
    
    def __str__(self):
        return f"Chat: {self.user1.get_full_name() or self.user1.email} - {self.user2.get_full_name() or self.user2.email}"


class StudyGroup(models.Model):
    """Модель для учебных групп"""
    name = models.CharField(max_length=100, verbose_name="Название группы")
    description = models.TextField(blank=True, null=True, verbose_name="Описание")
    creator = models.ForeignKey(User, on_delete=models.CASCADE, related_name='created_groups', verbose_name="Создатель")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField(default=True, verbose_name="Активна")
    max_members = models.IntegerField(default=20, verbose_name="Максимум участников")
    
    class Meta:
        ordering = ['-created_at']
        verbose_name = 'Учебная группа'
        verbose_name_plural = 'Учебные группы'
    
    def __str__(self):
        return f"{self.name} (создал: {self.creator.get_full_name() or self.creator.email})"
    
    def get_members_count(self):
        """Получить количество участников в группе"""
        return self.memberships.filter(status='accepted').count()
    
    def get_pending_requests_count(self):
        """Получить количество ожидающих заявок"""
        return self.memberships.filter(status='pending').count()
    
    def can_join(self):
        """Проверить, можно ли присоединиться к группе"""
        return self.is_active and self.get_members_count() < self.max_members
    
    def is_member(self, user):
        """Проверить, является ли пользователь участником группы"""
        return self.memberships.filter(user=user, status='accepted').exists()
    
    def is_creator(self, user):
        """Проверить, является ли пользователь создателем группы"""
        return self.creator == user


class StudyGroupMembership(models.Model):
    """Модель для членства в учебных группах"""
    STATUS_CHOICES = [
        ('pending', 'Ожидает подтверждения'),
        ('accepted', 'Принято'),
        ('declined', 'Отклонено'),
    ]
    
    ROLE_CHOICES = [
        ('member', 'Участник'),
        ('admin', 'Администратор'),
        ('creator', 'Создатель'),
    ]
    
    group = models.ForeignKey(StudyGroup, on_delete=models.CASCADE, related_name='memberships')
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_memberships')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending')
    role = models.CharField(max_length=10, choices=ROLE_CHOICES, default='member')
    joined_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        unique_together = ('group', 'user')
        ordering = ['-joined_at']
        verbose_name = 'Членство в группе'
        verbose_name_plural = 'Членства в группах'
    
    def __str__(self):
        return f"{self.user.get_full_name() or self.user.email} - {self.group.name} ({self.get_status_display()})"


class GroupChat(models.Model):
    """Модель для группового чата"""
    group = models.OneToOneField(StudyGroup, on_delete=models.CASCADE, related_name='chat')
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Групповой чат'
        verbose_name_plural = 'Групповые чаты'
    
    def __str__(self):
        return f"Чат группы: {self.group.name}"
    
    def get_last_message(self):
        """Получить последнее сообщение в группе"""
        return self.messages.order_by('-created_at').first()


class GroupMessage(models.Model):
    """Модель для сообщений в групповом чате"""
    MESSAGE_TYPES = [
        ('text', 'Текст'),
        ('image', 'Изображение'),
        ('file', 'Файл'),
        ('system', 'Системное'),
    ]
    
    chat = models.ForeignKey(GroupChat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='group_messages')
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPES, default='text')
    content = models.TextField(blank=True, null=True)  # Для текстовых сообщений
    file = models.FileField(upload_to='group_chat_files/', blank=True, null=True)  # Для файлов
    file_name = models.CharField(max_length=255, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    is_edited = models.BooleanField(default=False)
    edited_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        ordering = ['created_at']
        verbose_name = 'Сообщение в группе'
        verbose_name_plural = 'Сообщения в группе'
    
    def __str__(self):
        return f"{self.sender.get_full_name() or self.sender.email}: {self.content[:50]}..."


def chat_file_upload_path(instance, filename):
    """Путь для сохранения файлов чата"""
    import os
    import uuid
    from django.utils import timezone
    
    # Получаем расширение файла
    ext = os.path.splitext(filename)[1].lower()
    # Генерируем уникальное имя
    unique_filename = f"{uuid.uuid4()}{ext}"
    # Организуем по годам и месяцам
    date_path = timezone.now().strftime('%Y/%m')
    
    return f'chat_files/{date_path}/{unique_filename}'


class Message(models.Model):
    """Модель для сообщения в чате"""
    MESSAGE_TYPES = [
        ('text', 'Текст'),
        ('image', 'Изображение'),
        ('file', 'Файл'),
    ]
    
    chat = models.ForeignKey(Chat, on_delete=models.CASCADE, related_name='messages')
    sender = models.ForeignKey(User, on_delete=models.CASCADE, related_name='sent_messages')
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPES, default='text')
    content = models.TextField(blank=True, null=True)  # Для текстовых сообщений
    file = models.FileField(upload_to=chat_file_upload_path, blank=True, null=True)  # Для файлов
    file_name = models.CharField(max_length=255, blank=True, null=True)  # Оригинальное имя файла
    file_size = models.PositiveIntegerField(blank=True, null=True)  # Размер файла в байтах
    is_read = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['created_at']
        verbose_name = 'Сообщение'
        verbose_name_plural = 'Сообщения'
    
    @property
    def is_image(self):
        """Проверяет, является ли файл изображением"""
        if self.file:
            import os
            ext = os.path.splitext(self.file.name)[1].lower()
            return ext in ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']
        return False
    
    @property
    def file_size_human(self):
        """Возвращает размер файла в читаемом виде"""
        if not self.file_size:
            return ''
        
        size = self.file_size
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} TB"
    
    def save(self, *args, **kwargs):
        # Обновляем время последнего обновления чата
        if self.pk is None:  # Новое сообщение
            self.chat.updated_at = timezone.now()
            self.chat.save(update_fields=['updated_at'])
        
        # Сохраняем информацию о файле
        if self.file:
            if hasattr(self.file, 'name'):
                self.file_name = self.file.name.split('/')[-1] if '/' in self.file.name else self.file.name
            if hasattr(self.file, 'size'):
                self.file_size = self.file.size
            
            # Определяем тип сообщения
            if self.is_image:
                self.message_type = 'image'
            else:
                self.message_type = 'file'
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        if self.message_type == 'text':
            content_preview = (self.content[:50] + '...') if len(self.content) > 50 else self.content
            return f"{self.sender.get_full_name() or self.sender.email}: {content_preview}"
        else:
            return f"{self.sender.get_full_name() or self.sender.email}: [{self.message_type.upper()}] {self.file_name}"


class AIChat(models.Model):
    """Модель для чата с ИИ для изучения английского языка"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ai_chats')
    title = models.CharField('Название чата', max_length=200, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    is_active = models.BooleanField('Активный', default=True)
    
    class Meta:
        ordering = ['-updated_at']
        verbose_name = 'AI Чат'
        verbose_name_plural = 'AI Чаты'
    
    def get_last_message(self):
        """Получить последнее сообщение"""
        return self.ai_messages.order_by('-created_at').first()
    
    def get_messages_count(self):
        """Получить количество сообщений в чате"""
        return self.ai_messages.count()
    
    def __str__(self):
        title = self.title or f"AI Chat {self.id}"
        return f"{self.user.get_full_name() or self.user.email} - {title}"


class AIMessage(models.Model):
    """Модель для сообщения в AI чате"""
    SENDER_CHOICES = [
        ('user', 'Пользователь'),
        ('ai', 'ИИ'),
    ]
    
    ai_chat = models.ForeignKey(AIChat, on_delete=models.CASCADE, related_name='ai_messages')
    sender_type = models.CharField('Отправитель', max_length=10, choices=SENDER_CHOICES)
    content = models.TextField('Содержимое сообщения')
    original_language = models.CharField('Исходный язык', max_length=10, blank=True, null=True)
    translated_content = models.TextField('Переведенное содержимое', blank=True, null=True)
    translation_language = models.CharField('Язык перевода', max_length=10, blank=True, null=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    # Метаданные для ИИ
    ai_model = models.CharField('Модель ИИ', max_length=100, blank=True, null=True)
    ai_prompt_used = models.TextField('Использованный промпт', blank=True, null=True)
    response_time_ms = models.PositiveIntegerField('Время ответа (мс)', blank=True, null=True)
    
    class Meta:
        ordering = ['created_at']
        verbose_name = 'AI Сообщение'
        verbose_name_plural = 'AI Сообщения'
    
    def save(self, *args, **kwargs):
        # Обновляем время последнего обновления чата
        if self.pk is None:  # Новое сообщение
            self.ai_chat.updated_at = timezone.now()
            self.ai_chat.save(update_fields=['updated_at'])
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        content_preview = (self.content[:100] + '...') if len(self.content) > 100 else self.content
        sender_display = 'ИИ' if self.sender_type == 'ai' else 'Пользователь'
        return f"[{sender_display}]: {content_preview}"


class PromoCode(models.Model):
    """Модель промокодов для скидок на подписку"""
    code = models.CharField(max_length=50, unique=True, verbose_name='Промокод')
    discount_percent = models.PositiveIntegerField(verbose_name='Скидка (%)', help_text='Процент скидки от 0 до 100')
    valid_from = models.DateTimeField(verbose_name='Действует с')
    valid_until = models.DateTimeField(verbose_name='Действует до')
    is_active = models.BooleanField(default=True, verbose_name='Активен')
    usage_limit = models.PositiveIntegerField(null=True, blank=True, verbose_name='Лимит использований', help_text='Оставьте пустым для неограниченного использования')
    used_count = models.PositiveIntegerField(default=0, verbose_name='Количество использований')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Создан')
    
    class Meta:
        verbose_name = 'Промокод'
        verbose_name_plural = 'Промокоды'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.code} ({self.discount_percent}%)"
    
    def is_valid(self):
        """Проверяет, действителен ли промокод"""
        now = timezone.now()
        if not self.is_active:
            return False
        if now < self.valid_from or now > self.valid_until:
            return False
        if self.usage_limit and self.used_count >= self.usage_limit:
            return False
        return True
    
    def can_be_used(self):
        """Проверяет, можно ли использовать промокод"""
        return self.is_valid()


class Subscription(models.Model):
    """Модель подписок пользователей"""
    SUBSCRIPTION_TYPES = [
        ('free', 'Бесплатная'),
        ('medium', 'Medium'),
        ('pro', 'Pro'),
        ('ultra', 'Ultra'),
    ]
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='subscription', verbose_name='Пользователь')
    subscription_type = models.CharField(max_length=10, choices=SUBSCRIPTION_TYPES, default='free', verbose_name='Тип подписки')
    start_date = models.DateTimeField(auto_now_add=True, verbose_name='Дата начала')
    end_date = models.DateTimeField(null=True, blank=True, verbose_name='Дата окончания')
    is_active = models.BooleanField(default=True, verbose_name='Активна')
    auto_renewal = models.BooleanField(default=False, verbose_name='Автопродление')
    promo_code = models.ForeignKey(PromoCode, on_delete=models.SET_NULL, null=True, blank=True, verbose_name='Использованный промокод')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Создана')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Обновлена')
    
    class Meta:
        verbose_name = 'Подписка'
        verbose_name_plural = 'Подписки'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.email} - {self.get_subscription_type_display()}"
    
    def is_valid(self):
        """Проверяет, действительна ли подписка"""
        if not self.is_active:
            return False
        if self.end_date and timezone.now() > self.end_date:
            return False
        return True
    
    def get_remaining_days(self):
        """Возвращает количество оставшихся дней подписки"""
        if not self.end_date:
            return None
        remaining = self.end_date - timezone.now()
        return max(0, remaining.days)
    
    def extend_subscription(self, months=1):
        """Продлевает подписку на указанное количество месяцев"""
        if self.end_date:
            self.end_date += timedelta(days=30 * months)
        else:
            self.end_date = timezone.now() + timedelta(days=30 * months)
        self.save()
    
    @property
    def is_premium(self):
        """Проверяет, является ли подписка премиум"""
        return self.subscription_type in ['medium', 'pro', 'ultra']


class Payment(models.Model):
    """Модель платежей"""
    STATUS_CHOICES = [
        ('pending', 'Ожидает оплаты'),
        ('paid', 'Оплачен'),
        ('failed', 'Неудачный'),
        ('cancelled', 'Отменен'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='payments', verbose_name='Пользователь')
    subscription = models.ForeignKey(Subscription, on_delete=models.CASCADE, related_name='payments', verbose_name='Подписка')
    amount = models.DecimalField(max_digits=10, decimal_places=2, verbose_name='Сумма')
    currency = models.CharField(max_length=3, default='RUB', verbose_name='Валюта')
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='pending', verbose_name='Статус')
    yookassa_payment_id = models.CharField(max_length=100, null=True, blank=True, verbose_name='ID платежа ЮKassa')
    payment_url = models.URLField(null=True, blank=True, verbose_name='Ссылка на оплату')
    promo_code = models.ForeignKey(PromoCode, on_delete=models.SET_NULL, null=True, blank=True, verbose_name='Промокод')
    discount_amount = models.DecimalField(max_digits=10, decimal_places=2, default=0, verbose_name='Размер скидки')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Создан')
    updated_at = models.DateTimeField(auto_now=True, verbose_name='Обновлен')
    
    class Meta:
        verbose_name = 'Платеж'
        verbose_name_plural = 'Платежи'
        ordering = ['-created_at']
    
    def __str__(self):
        return f"{self.user.email} - {self.amount} {self.currency} ({self.get_status_display()})"


class LanguageLevelTest(models.Model):
    """Модель теста для определения уровня языка"""
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='language_tests', verbose_name='Пользователь')
    questions = models.JSONField(verbose_name='Вопросы теста', help_text='Список вопросов с ответами пользователя', null=True, blank=True, default=list)
    answers = models.JSONField(verbose_name='Ответы пользователя', default=list, blank=True)
    ai_analysis = models.JSONField(verbose_name='Анализ AI', null=True, blank=True)
    detected_level = models.CharField(
        max_length=2,
        choices=[('A1', 'A1'), ('A2', 'A2'), ('B1', 'B1'), ('B2', 'B2'), ('C1', 'C1'), ('C2', 'C2')],
        null=True,
        blank=True,
        verbose_name='Определенный уровень'
    )
    recommended_topics = models.JSONField(verbose_name='Рекомендуемые темы', default=list, blank=True)
    score = models.IntegerField(null=True, blank=True, verbose_name='Балл')
    max_score = models.IntegerField(default=100, verbose_name='Максимальный балл')
    completed_at = models.DateTimeField(null=True, blank=True, verbose_name='Завершен')
    created_at = models.DateTimeField(auto_now_add=True, verbose_name='Создан')
    
    class Meta:
        verbose_name = 'Тест уровня языка'
        verbose_name_plural = 'Тесты уровня языка'
        ordering = ['-created_at']
    
    def __str__(self):
        level = self.detected_level or 'Не определен'
        return f"{self.user.email} - {level} ({self.created_at.strftime('%d.%m.%Y')})"
    
    def is_completed(self):
        return self.completed_at is not None

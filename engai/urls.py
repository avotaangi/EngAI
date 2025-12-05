"""
URL configuration for engai project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/4.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/', include('notifications.api_urls')),  # API endpoints
    path('notifications/', include('notifications.urls')),  # Страница уведомлений
    path('dashboard/', views.dashboard_view, name='dashboard'),  # Главная страница dashboard
    path('level-test/', views.level_test_view, name='level_test'),  # Страница теста уровня языка
    path('api/level-test/start/', views.start_level_test, name='start_level_test'),  # Начать тест уровня
    path('api/level-test/submit/', views.submit_level_test, name='submit_level_test'),  # Отправить ответы
    path('', include('users.urls')),
    path('dictionary/', include('dictionary.urls')),
    path('cards/', include('cards.urls')),
    path('modules/', include('study_modules.urls')),
    path('', include('social_django.urls', namespace='social')),
    path('text-check/', include('text_check.urls')),
    path('deadlines/', include('deadlines.urls')),  # API для дедлайнов
    # Для тестирования страницы 404 в режиме DEBUG=True
    path('404-test/', views.page_not_found_view, name='404_test'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT) + static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)

# Кастомные обработчики ошибок
handler404 = 'engai.views.custom_404_view'
handler500 = 'engai.views.custom_500_view'

from django.shortcuts import render, get_object_or_404, redirect
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.http import require_http_methods, require_POST
from django.views.decorators.csrf import csrf_exempt
from .models import Folder, Module, Card, LearningProgress, BubbleGameRecord, BalloonGameRecord
from users.models import AIChat, AIMessage
import json
import logging
from django.contrib import messages
from django.utils import timezone
from datetime import timedelta
import requests
from bs4 import BeautifulSoup
import re
import random
from django.apps import apps
from django.db.models import Q
import os
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage
from dotenv import load_dotenv
from gtts import gTTS
import asyncio
try:
    import edge_tts  # Neural voices without API keys
except Exception:  # pragma: no cover
    edge_tts = None
import time
from django.conf import settings
import tempfile
from typing import Optional

try:
    from faster_whisper import WhisperModel  # Optional ASR
except Exception:
    WhisperModel = None  # type: ignore

_WHISPER_MODEL: Optional[object] = None

def _get_whisper_model():
    global _WHISPER_MODEL
    if _WHISPER_MODEL is not None:
        return _WHISPER_MODEL
    if WhisperModel is None:
        return None
    try:
        # Lightweight default; switch to "small"/"medium" if CPU allows
        _WHISPER_MODEL = WhisperModel("base", device="cpu", compute_type="int8")
        return _WHISPER_MODEL
    except Exception as e:
        logger.warning(f"Whisper model init failed: {e}")
        return None

logger = logging.getLogger(__name__)

@login_required
def ai_speak(request):
    return render(request, 'cards/ai_speak.html')

@login_required
def media_center(request):
    return render(request, 'cards/media_center.html')

@login_required
def media_detail(request, media_type, media_id):
    """
    Страница просмотра фильма/сериала с детальной информацией
    """
    tmdb_api_key = os.getenv('TMDB_API_KEY', '')
    if not tmdb_api_key:
        tmdb_api_key = '1f54bd990f1cdfb230adb312546d765d'
    
    base_url = 'https://api.themoviedb.org/3'
    headers = {'accept': 'application/json'}
    
    try:
        if media_type == 'movie':
            url = f'{base_url}/movie/{media_id}'
            params = {'api_key': tmdb_api_key, 'language': 'en-US', 'append_to_response': 'videos,credits'}
        else:  # tv
            url = f'{base_url}/tv/{media_id}'
            params = {'api_key': tmdb_api_key, 'language': 'en-US', 'append_to_response': 'videos,credits'}
        
        response = requests.get(url, params=params, headers=headers, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        # Получаем постер и backdrop
        poster_path = data.get('poster_path')
        backdrop_path = data.get('backdrop_path')
        poster_url = f"https://image.tmdb.org/t/p/w500{poster_path}" if poster_path else None
        backdrop_url = f"https://image.tmdb.org/t/p/w1280{backdrop_path}" if backdrop_path else None
        
        # Получаем видео (трейлеры)
        videos = data.get('videos', {}).get('results', [])
        trailer = None
        for video in videos:
            if video.get('type') == 'Trailer' and video.get('site') == 'YouTube':
                trailer = video.get('key')
                break
        
        # Получаем актеров
        credits = data.get('credits', {})
        cast = credits.get('cast', [])[:10]  # Первые 10 актеров
        
        # Получаем жанры
        genres = [g.get('name') for g in data.get('genres', [])]
        
        context = {
            'media': data,
            'poster_url': poster_url,
            'backdrop_url': backdrop_url,
            'trailer_key': trailer,
            'cast': cast,
            'genres': genres,
            'media_type': media_type,
            'media_id': media_id
        }
        
        return render(request, 'cards/media_detail.html', context)
        
    except requests.RequestException as exc:
        logger.error(f"Media detail request failed ({media_type}/{media_id}): {exc}")
        messages.error(request, 'Не удалось загрузить информацию о фильме.')
        return redirect('cards:media_center')

@login_required
@require_http_methods(["POST"])
def generate_media_lexicon(request, media_type, media_id):
    """
    Генерирует лексику фильма/сериала через ИИ
    """
    try:
        data = json.loads(request.body)
        media_title = data.get('title', '')
        
        api_key = os.getenv('MISTRAL_API_KEY')
        if not api_key:
            return JsonResponse({'error': 'AI не настроен'}, status=500)
        
        # Промпт для генерации лексики
        prompt = f"""Ты — эксперт по изучению английского языка через фильмы и сериалы.
Проанализируй фильм/сериал "{media_title}" и создай список полезной лексики для изучения английского языка.

Формат ответа (строго JSON):
{{
  "words": [
    {{
      "word": "слово на английском",
      "translation": "перевод на русский",
      "example": "пример использования из фильма или контекста",
      "level": "A1/A2/B1/B2/C1/C2"
    }}
  ],
  "phrases": [
    {{
      "phrase": "фраза на английском",
      "translation": "перевод на русский",
      "example": "пример использования",
      "level": "A1/A2/B1/B2/C1/C2"
    }}
  ],
  "grammar": [
    {{
      "topic": "грамматическая тема",
      "explanation": "краткое объяснение",
      "example": "пример из фильма"
    }}
  ]
}}

Требования:
- Выбери 15-20 самых полезных слов
- Выбери 5-10 полезных фраз
- Укажи 2-3 грамматические темы
- Примеры должны быть релевантными к фильму
- Уровни сложности должны соответствовать CEFR
- Ответ только JSON, без дополнительного текста"""

        client = MistralClient(api_key=api_key)
        chat_messages = [
            ChatMessage(role="user", content=prompt)
        ]
        
        resp = client.chat(model="mistral-small", messages=chat_messages, temperature=0.7)
        raw_reply = resp.choices[0].message.content if getattr(resp, 'choices', None) else '{"words":[],"phrases":[],"grammar":[]}'
        
        # Очищаем от markdown
        clean_reply = raw_reply.strip()
        if clean_reply.startswith('```'):
            lines = clean_reply.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            clean_reply = '\n'.join(lines).strip()
        
        # Парсим JSON
        try:
            lexicon_data = json.loads(clean_reply)
            return JsonResponse(lexicon_data)
        except Exception as parse_err:
            logger.warning(f"Failed to parse lexicon: {parse_err}. Raw: {raw_reply[:200]}")
            return JsonResponse({
                'error': 'Не удалось обработать ответ ИИ',
                'words': [],
                'phrases': [],
                'grammar': []
            })
        
    except Exception as e:
        logger.error(f"Ошибка генерации лексики: {e}")
        return JsonResponse({'error': 'Ошибка при генерации лексики'}, status=500)

load_dotenv()

@login_required
def cards_view(request):
    logger.info(f"User {request.user.username} accessed cards view")
    
    # Получаем все папки пользователя
    folders = Folder.objects.filter(user=request.user, parent=None)
    
    # Получаем все модули пользователя
    modules = Module.objects.filter(user=request.user)
    
    context = {
        'folders': folders,
        'modules': modules,
    }
    
    return render(request, 'cards/cards.html', context)

@login_required
def module_view(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    
    # Проверяем, принадлежит ли модуль текущему пользователю
    is_owner = (module.user == request.user)
    
    return render(request, 'cards/module.html', {
        'module': module,
        'is_owner': is_owner
    })

@login_required
def folder_view(request, folder_id):
    folder = get_object_or_404(Folder, id=folder_id, user=request.user)
    modules = Module.objects.filter(folder=folder).select_related('user')
    
    # Получаем подпапки текущей папки
    subfolders = Folder.objects.filter(parent=folder, user=request.user)
    
    # Получаем путь навигации (хлебные крошки)
    breadcrumbs = []
    current_folder = folder
    while current_folder:
        breadcrumbs.insert(0, current_folder)
        current_folder = current_folder.parent
    
    # Форматируем данные модулей для отображения
    for module in modules:
        module.formatted_user = f"{module.user.first_name} {module.user.last_name}".strip() or module.user.email if module.user else 'Неизвестный автор'
    
    context = {
        'folder': folder,
        'modules': modules,
        'subfolders': subfolders,
        'breadcrumbs': breadcrumbs
    }
    
    return render(request, 'cards/folder.html', context)

@login_required
@require_http_methods(["GET"])
def get_folders(request):
    try:
        logger.info(f"User {request.user.username} requested folders")
        
        # Получаем только корневые папки пользователя (без родительской папки)
        folders = Folder.objects.filter(user=request.user, parent=None)
        folders_data = []
        
        for folder in folders:
            # Проверяем наличие подпапок и модулей
            has_children = Folder.objects.filter(parent=folder).exists()
            has_modules = Module.objects.filter(folder=folder).exists()
            
            folders_data.append({
                'id': folder.id,
                'name': folder.name,
                'parent_id': None,
                'has_children': has_children,
                'has_modules': has_modules
            })
        
        logger.info(f"Found {len(folders_data)} root folders for user {request.user.username}")
        return JsonResponse({
            'folders': folders_data
        })
    except Exception as e:
        logger.error(f"Error getting folders for user {request.user.username}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def get_modules(request, folder_id=None):
    try:
        logger.info(f"User {request.user.username} requested modules (folder_id: {folder_id})")
        
        # Получаем все модули пользователя
        modules = Module.objects.filter(user=request.user).select_related('user')
        
        # Если указан folder_id, фильтруем по папке
        if folder_id:
            modules = modules.filter(folder_id=folder_id)
        
        modules_data = [{
            'id': module.id,
            'name': module.name,
            'type': module.module_type,
            'is_saved': module.is_saved,
            'user': f"{module.user.first_name} {module.user.last_name}".strip() or module.user.email if module.user else 'Неизвестный автор'
        } for module in modules]
        
        logger.info(f"Found {len(modules_data)} modules for user {request.user.username}")
        return JsonResponse({
            'modules': modules_data
        })
    except Exception as e:
        logger.error(f"Error getting modules for user {request.user.username}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def get_saved_modules(request):
    try:
        # Получаем все сохраненные модули
        modules = Module.objects.filter(is_saved=True).select_related('user')
        
        modules_data = [{
            'id': module.id,
            'name': module.name,
            'type': module.module_type,
            'is_saved': module.is_saved,
            'user': f"{module.user.first_name} {module.user.last_name}".strip() or module.user.email if module.user else 'Неизвестный автор'
        } for module in modules]
        
        return JsonResponse({
            'modules': modules_data
        })
    except Exception as e:
        logger.error(f"Error getting saved modules: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def create_folder(request):
    try:
        data = json.loads(request.body)
        name = data.get('name')
        parent_id = data.get('parent_id')
        
        if not name:
            return JsonResponse({'error': 'Название папки обязательно'}, status=400)
        
        parent = None
        if parent_id:
            try:
                parent = Folder.objects.get(id=parent_id, user=request.user)
            except Folder.DoesNotExist:
                return JsonResponse({'error': 'Родительская папка не найдена'}, status=404)
        
        folder = Folder.objects.create(
            user=request.user,
            name=name,
            parent=parent
        )
        
        return JsonResponse({
            'id': folder.id,
            'name': folder.name,
            'parent_id': folder.parent.id if folder.parent else None,
            'has_children': False
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат данных'}, status=400)
    except Exception as e:
        logger.error(f"Error creating folder: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def create_module(request):
    try:
        data = json.loads(request.body)
        name = data.get('name')
        module_type = data.get('type', 'private')
        folder_id = data.get('folder_id')
        
        if not name:
            return JsonResponse({'error': 'Название модуля обязательно'}, status=400)
        
        folder = None
        if folder_id:
            try:
                folder = Folder.objects.get(id=folder_id, user=request.user)
            except Folder.DoesNotExist:
                return JsonResponse({'error': 'Папка не найдена'}, status=404)
        
        module = Module.objects.create(
            user=request.user,
            name=name,
            module_type=module_type,
            folder=folder
        )
        
        return JsonResponse({
            'id': module.id,
            'name': module.name,
            'type': module.module_type
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат данных'}, status=400)
    except Exception as e:
        logger.error(f"Error creating module: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def save_module(request, module_id):
    try:
        module = get_object_or_404(Module, id=module_id)
        
        # Проверяем, не является ли модуль уже сохраненным
        if module.is_saved:
            return JsonResponse({'status': 'success', 'message': 'Модуль уже сохранен'})
        
        # Проверяем, не является ли модуль созданным текущим пользователем
        if module.user == request.user:
            return JsonResponse({'error': 'Нельзя сохранить свой собственный модуль'}, status=400)
        
        # Сохраняем модуль
        module.is_saved = True
        module.save()
        
        return JsonResponse({
            'status': 'success',
            'message': 'Модуль успешно сохранен'
        })
    except Exception as e:
        logger.error(f"Error saving module: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["GET"])
def get_module_cards(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    cards = module.cards.all()
    return JsonResponse({
        'cards': [{
            'id': card.id,
            'term': card.term,
            'translation': card.translation,
            'image': card.image.url if card.image else None
        } for card in cards]
    })

@login_required
@csrf_exempt
@require_http_methods(["POST"])
def create_card(request, module_id):
    try:
        module = get_object_or_404(Module, id=module_id)
        term = request.POST.get('term')
        translation = request.POST.get('translation')
        image = request.FILES.get('image')
        
        if not term or not translation:
            return JsonResponse({'error': 'Missing term or translation'}, status=400)
        
        card = Card.objects.create(
            module=module,
            term=term,
            translation=translation,
            image=image
        )
        
        return JsonResponse({
            'id': card.id,
            'term': card.term,
            'translation': card.translation,
            'image': card.image.url if card.image else None
        })
    except Exception as e:
        logger.error(f"Error creating card: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@csrf_exempt
@require_http_methods(["POST"])
def update_card_image(request, card_id):
    try:
        card = get_object_or_404(Card, id=card_id)
        if 'image' not in request.FILES:
            return JsonResponse({'error': 'No image provided'}, status=400)
        
        card.image = request.FILES['image']
        card.save()
        
        return JsonResponse({
            'id': card.id,
            'image': card.image.url
        })
    except Exception as e:
        logger.error(f"Error updating card image: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def update_module(request, module_id):
    try:
        module = get_object_or_404(Module, id=module_id, user=request.user)
        data = json.loads(request.body)
        
        if 'name' in data:
            module.name = data['name']
        if 'type' in data:
            module.module_type = data['type']
        if 'folder_id' in data:
            folder_id = data['folder_id']
            if folder_id:
                try:
                    folder = Folder.objects.get(id=folder_id, user=request.user)
                    module.folder = folder
                except Folder.DoesNotExist:
                    return JsonResponse({'error': 'Папка не найдена'}, status=404)
            else:
                module.folder = None
        
        module.save()
        
        return JsonResponse({
            'id': module.id,
            'name': module.name,
            'type': module.module_type,
            'folder_id': module.folder.id if module.folder else None,
            'user': f"{module.user.first_name} {module.user.last_name}".strip() or module.user.email if module.user else 'Неизвестный автор'
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат данных'}, status=400)
    except Exception as e:
        logger.error(f"Error updating module: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def update_card(request, card_id):
    try:
        card = get_object_or_404(Card, id=card_id, module__user=request.user)
        
        if 'term' in request.POST:
            card.term = request.POST['term']
        if 'translation' in request.POST:
            card.translation = request.POST['translation']
        if 'image' in request.FILES:
            card.image = request.FILES['image']
        
        card.save()
        
        return JsonResponse({
            'id': card.id,
            'term': card.term,
            'translation': card.translation,
            'image': card.image.url if card.image else None
        })
    except Exception as e:
        logger.error(f"Error updating card: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["DELETE"])
def delete_card(request, card_id):
    try:
        card = get_object_or_404(Card, id=card_id, module__user=request.user)
        card.delete()
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"Error deleting card: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["DELETE"])
def delete_module(request, module_id):
    try:
        module = get_object_or_404(Module, id=module_id, user=request.user)
        module.delete()
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"Error deleting module: {str(e)}")
        return JsonResponse({'error': 'Ошибка при удалении модуля'}, status=500)

@login_required
@require_http_methods(["GET"])
def get_module(request, module_id):
     module = get_object_or_404(Module, id=module_id)
     return JsonResponse({
       'id': module.id,
        'name': module.name,
        'type': module.module_type,
        'folder_id': module.folder.id if module.folder else None
       })

@login_required
@require_http_methods(["POST"])
def update_folder(request, folder_id):
    try:
        folder = get_object_or_404(Folder, id=folder_id, user=request.user)
        data = json.loads(request.body)
        
        if 'name' in data:
            folder.name = data['name']
        if 'parent_id' in data:
            parent_id = data['parent_id']
            if parent_id:
                try:
                    parent = Folder.objects.get(id=parent_id, user=request.user)
                    folder.parent = parent
                except Folder.DoesNotExist:
                    return JsonResponse({'error': 'Родительская папка не найдена'}, status=404)
            else:
                folder.parent = None
        
        folder.save()
        
        return JsonResponse({
            'id': folder.id,
            'name': folder.name,
            'parent_id': folder.parent.id if folder.parent else None,
            'has_children': Folder.objects.filter(parent=folder).exists()
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат данных'}, status=400)
    except Exception as e:
        logger.error(f"Error updating folder: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_http_methods(["DELETE"])
def delete_folder(request, folder_id):
    try:
        folder = get_object_or_404(Folder, id=folder_id, user=request.user)
        
        # Проверяем, есть ли подпапки или модули
        if Folder.objects.filter(parent=folder).exists():
            return JsonResponse({'error': 'Невозможно удалить папку, содержащую подпапки'}, status=400)
        if Module.objects.filter(folder=folder).exists():
            return JsonResponse({'error': 'Невозможно удалить папку, содержащую модули'}, status=400)
        
        folder.delete()
        return JsonResponse({'status': 'success'})
    except Exception as e:
        logger.error(f"Error deleting folder: {str(e)}")
        return JsonResponse({'error': 'Ошибка при удалении папки'}, status=500)

@login_required
def learn_module(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    cards = list(module.cards.all())
    
    if not cards:
        return redirect('cards:module', module_id=module_id)
    
    # Получаем или создаем прогресс обучения для каждой карточки
    for card in cards:
        progress, created = LearningProgress.objects.get_or_create(
            user=request.user,
            card=card,
            module=module
        )
    
    # Получаем карточки, которые требуют повторения
    cards_to_review = LearningProgress.objects.filter(
        user=request.user,
        module=module,
        needs_review=True
    ).select_related('card')
    
    # Если есть карточки для повторения, добавляем их в начало списка
    review_cards = [progress.card for progress in cards_to_review]
    remaining_cards = [card for card in cards if card not in review_cards]
    cards = review_cards + remaining_cards
    
    context = {
        'module': module,
        'cards': json.dumps([{
            'id': card.id,
            'term': card.term,
            'translation': card.translation
        } for card in cards]),
        'total_cards': len(cards)
    }
    
    return render(request, 'cards/learn.html', context)

@login_required
@require_POST
def update_learning_progress(request):
    try:
        data = json.loads(request.body)
        card_id = data.get('card_id')
        module_id = data.get('module_id')
        is_correct = data.get('is_correct')
        
        if not all([card_id, module_id, is_correct is not None]):
            return JsonResponse({'error': 'Missing required fields'}, status=400)
        
        progress = get_object_or_404(
            LearningProgress,
            user=request.user,
            card_id=card_id,
            module_id=module_id
        )
        
        progress.update_progress(is_correct)
        
        return JsonResponse({
            'success': True,
            'needs_review': progress.needs_review,
            'correct_attempts': progress.correct_attempts,
            'incorrect_attempts': progress.incorrect_attempts
        })
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=400)

@login_required
@require_POST
def import_quizlet(request):
    try:
        data = json.loads(request.body)
        url = data.get('url')
        name = data.get('name')
        module_type = data.get('type', 'private')
        folder_id = data.get('folder_id')
        
        if not url:
            return JsonResponse({'error': 'URL не указан'}, status=400)
            
        if not name:
            return JsonResponse({'error': 'Название модуля обязательно'}, status=400)
        
        # Извлекаем ID набора из URL
        set_id = None
        if 'quizlet.com' in url:
            # Пробуем разные форматы URL
            if '/set/' in url:
                set_id = url.split('/set/')[1].split('/')[0]
            elif '/ru/' in url:
                set_id = url.split('/ru/')[1].split('/')[0]
            else:
                # Ищем ID в URL
                import re
                match = re.search(r'/(\d+)/', url)
                if match:
                    set_id = match.group(1)
        
        if not set_id:
            return JsonResponse({'error': 'Не удалось определить ID набора Quizlet'}, status=400)
        
        # Создаем новый модуль
        folder = None
        if folder_id:
            try:
                folder = Folder.objects.get(id=folder_id, user=request.user)
            except Folder.DoesNotExist:
                return JsonResponse({'error': 'Папка не найдена'}, status=404)
        
        module = Module.objects.create(
            user=request.user,
            name=name,
            module_type=module_type,
            folder=folder
        )
        
        # Получаем данные через API Quizlet
        api_url = f'https://api.quizlet.com/2.0/sets/{set_id}'
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        
        response = requests.get(api_url, headers=headers)
        if response.status_code != 200:
            # Если API не работает, пробуем получить данные через веб-страницу
            response = requests.get(url, headers=headers)
            if response.status_code != 200:
                module.delete()
                return JsonResponse({'error': 'Не удалось получить данные из Quizlet. Проверьте правильность ссылки.'}, status=400)
            
            soup = BeautifulSoup(response.text, 'html.parser')
            cards_data = []
            
            # Ищем карточки в HTML
            card_elements = soup.find_all('div', class_='SetPageTerm-content')
            if not card_elements:
                card_elements = soup.find_all('div', class_='SetPageTerm')
            
            for card in card_elements:
                term_element = card.find('div', class_='SetPageTerm-wordText') or card.find('div', class_='SetPageTerm-word')
                translation_element = card.find('div', class_='SetPageTerm-definitionText') or card.find('div', class_='SetPageTerm-definition')
                
                if not term_element or not translation_element:
                    continue
                    
                term = term_element.text.strip()
                translation = translation_element.text.strip()
                
                if term and translation:
                    Card.objects.create(
                        module=module,
                        term=term,
                        translation=translation
                    )
                    cards_data.append({
                        'term': term,
                        'translation': translation
                    })
        else:
            # Используем данные из API
            data = response.json()
            cards_data = []
            
            for card in data.get('terms', []):
                term = card.get('term', '').strip()
                translation = card.get('definition', '').strip()
                
                if term and translation:
                    Card.objects.create(
                        module=module,
                        term=term,
                        translation=translation
                    )
                    cards_data.append({
                        'term': term,
                        'translation': translation
                    })
        
        if not cards_data:
            module.delete()
            return JsonResponse({'error': 'Не удалось импортировать карточки. Проверьте формат набора.'}, status=400)
        
        return JsonResponse({
            'success': True,
            'module_id': module.id,
            'cards_count': len(cards_data)
        })
        
    except requests.RequestException as e:
        return JsonResponse({'error': f'Ошибка при получении данных из Quizlet: {str(e)}'}, status=400)
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат данных'}, status=400)
    except Exception as e:
        logger.error(f"Error importing from Quizlet: {str(e)}")
        return JsonResponse({'error': f'Ошибка при импорте: {str(e)}'}, status=500)

@login_required
@require_http_methods(["GET"])
def search_content(request):
    try:
        search_term = request.GET.get('q', '').lower()
        filter_type = request.GET.get('filter', 'all')
        
        # Получаем папки пользователя
        folders = []
        if filter_type in ['all', 'folders']:
            user_folders = Folder.objects.filter(
                user=request.user,
                name__icontains=search_term
            )
            for folder in user_folders:
                has_children = Folder.objects.filter(parent=folder).exists()
                has_modules = Module.objects.filter(folder=folder).exists()
                folders.append({
                    'id': folder.id,
                    'name': folder.name,
                    'has_children': has_children,
                    'has_modules': has_modules
                })
        
        # Получаем модули
        modules = []
        if filter_type in ['all', 'modules']:
            # Ищем модули по названию
            modules_query = Module.objects.filter(
                name__icontains=search_term
            ).select_related('user')
            
            # Если это не поиск по папкам, добавляем поиск по содержимому карточек
            if filter_type != 'folders':
                # Ищем модули, содержащие карточки с искомым текстом
                card_modules = Module.objects.filter(
                    cards__term__icontains=search_term
                ) | Module.objects.filter(
                    cards__translation__icontains=search_term
                )
                modules_query = modules_query | card_modules
            
            # Фильтруем по типу модуля
            if filter_type == 'modules':
                modules_query = modules_query.filter(module_type='public')
            
            # Убираем дубликаты
            modules_query = modules_query.distinct()
            
            for module in modules_query:
                # Получаем карточки, содержащие искомый текст
                matching_cards = []
                if search_term:
                    matching_cards = module.cards.filter(
                        term__icontains=search_term
                    ) | module.cards.filter(
                        translation__icontains=search_term
                    )
                
                modules.append({
                    'id': module.id,
                    'name': module.name,
                    'type': module.module_type,
                    'is_saved': module.is_saved,
                    'user': f"{module.user.first_name} {module.user.last_name}".strip() or module.user.email if module.user else 'Неизвестный автор',
                    'matching_cards': [{
                        'term': card.term,
                        'translation': card.translation
                    } for card in matching_cards[:3]] if matching_cards else []
                })
        
        return JsonResponse({
            'folders': folders,
            'modules': modules
        })
    except Exception as e:
        logger.error(f"Error searching content: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def module_test(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    cards = Card.objects.filter(module=module)
    total_cards = cards.count()
    
    context = {
        'module': module,
        'total_cards': total_cards,
    }
    
    return render(request, 'cards/test.html', context)

@login_required
def bubble_game(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    cards = Card.objects.filter(module=module)
    total_cards = cards.count()
    
    # Получаем текущий рекорд пользователя для данного модуля
    try:
        user_record = BubbleGameRecord.objects.filter(
            user=request.user,
            module=module
        ).order_by('time_seconds').first()
        
        if user_record:
            minutes = user_record.time_seconds // 60
            seconds = user_record.time_seconds % 60
            record_time = f"{minutes:02d}:{seconds:02d}"
        else:
            record_time = "--:--"
    except Exception as e:
        logger.error(f"Error getting bubble game record: {str(e)}")
        record_time = "--:--"
    
    context = {
        'module': module,
        'total_cards': total_cards,
        'record_time': record_time
    }
    
    return render(request, 'cards/bubble_game.html', context)

@login_required
@require_http_methods(["GET"])
def get_bubble_game_record(request, module_id):
    try:
        module = get_object_or_404(Module, id=module_id)
        
        # Получаем текущий рекорд пользователя
        user_record = BubbleGameRecord.objects.filter(
            user=request.user,
            module=module
        ).order_by('time_seconds').first()
        
        if user_record:
            minutes = user_record.time_seconds // 60
            seconds = user_record.time_seconds % 60
            
            return JsonResponse({
                'has_record': True,
                'time_seconds': user_record.time_seconds,
                'time_formatted': f"{minutes:02d}:{seconds:02d}",
                'correct_answers': user_record.correct_answers,
                'incorrect_answers': user_record.incorrect_answers
            })
        else:
            return JsonResponse({
                'has_record': False,
                'time_formatted': "--:--"
            })
    except Exception as e:
        logger.error(f"Error getting bubble game record: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
@require_POST
def save_bubble_game_record(request, module_id):
    try:
        logger.info(f"[РЕКОРД] Получен запрос на сохранение рекорда от пользователя {request.user.username} для модуля {module_id}")
        logger.info(f"[РЕКОРД] Заголовки запроса: {request.headers}")
        
        # Проверяем, что модель BubbleGameRecord зарегистрирована в приложении
        try:
            BubbleGameRecord = apps.get_model('cards', 'BubbleGameRecord')
            logger.info("[РЕКОРД] Модель BubbleGameRecord успешно импортирована")
        except LookupError as e:
            logger.error(f"[РЕКОРД] Ошибка импорта модели BubbleGameRecord: {str(e)}")
            return JsonResponse({'error': 'Серверная ошибка: модель рекордов не найдена'}, status=500)
        
        # Пробуем разные способы получения данных
        data = None
        if 'application/json' in request.content_type:
            try:
                data = json.loads(request.body.decode('utf-8'))
                logger.info(f"[РЕКОРД] Получены JSON данные: {data}")
            except json.JSONDecodeError as e:
                logger.error(f"[РЕКОРД] Ошибка декодирования JSON: {str(e)}")
                logger.error(f"[РЕКОРД] Содержимое request.body: {request.body}")
                return JsonResponse({'error': 'Неверный формат JSON'}, status=400)
        else:
            data = request.POST
            logger.info(f"[РЕКОРД] Получены POST данные: {data}")
        
        if not data:
            logger.error("[РЕКОРД] Данные не получены ни в JSON, ни в POST")
            return JsonResponse({'error': 'Данные не получены'}, status=400)
        
        module = get_object_or_404(Module, id=module_id)
        logger.info(f"[РЕКОРД] Модуль найден: {module.name}")
        
        time_seconds = data.get('time_seconds')
        correct_answers = data.get('correct_answers', 0)
        incorrect_answers = data.get('incorrect_answers', 0)
        
        # Логируем полученные данные
        logger.info(f"[РЕКОРД] Время: {time_seconds}, правильные: {correct_answers}, неправильные: {incorrect_answers}")
        
        if not time_seconds:
            logger.error("[РЕКОРД] Время не указано в запросе")
            return JsonResponse({'error': 'Время не указано'}, status=400)
        
        # Конвертируем в числа
        try:
            time_seconds = int(time_seconds)
            correct_answers = int(correct_answers)
            incorrect_answers = int(incorrect_answers)
        except (ValueError, TypeError) as e:
            logger.error(f"[РЕКОРД] Ошибка конвертации типов: {str(e)}")
            return JsonResponse({'error': 'Неверный формат данных'}, status=400)
        
        # Проверяем, есть ли уже рекорд с лучшим временем
        try:
            existing_record = BubbleGameRecord.objects.filter(
                user=request.user,
                module=module
            ).order_by('time_seconds').first()
            
            if existing_record:
                logger.info(f"[РЕКОРД] Найден существующий рекорд: {existing_record.time_seconds} сек.")
            else:
                logger.info("[РЕКОРД] Существующих рекордов не найдено")
                
            is_new_record = False
            
            if not existing_record or existing_record.time_seconds > time_seconds:
                # Создаем новый рекорд, если его нет или он хуже текущего результата
                try:
                    record = BubbleGameRecord.objects.create(
                        user=request.user,
                        module=module,
                        time_seconds=time_seconds,
                        correct_answers=correct_answers,
                        incorrect_answers=incorrect_answers
                    )
                    is_new_record = True
                    logger.info(f"[РЕКОРД] Создан новый рекорд: {record}")
                except Exception as e:
                    logger.error(f"[РЕКОРД] Ошибка при создании записи в БД: {str(e)}", exc_info=True)
                    return JsonResponse({'error': f'Ошибка при сохранении рекорда: {str(e)}'}, status=500)
                
                minutes = time_seconds // 60
                seconds = time_seconds % 60
                
                response_data = {
                    'success': True,
                    'is_new_record': is_new_record,
                    'time_seconds': time_seconds,
                    'time_formatted': f"{minutes:02d}:{seconds:02d}"
                }
                logger.info(f"[РЕКОРД] Отправка ответа с новым рекордом: {response_data}")
                return JsonResponse(response_data)
            else:
                minutes = existing_record.time_seconds // 60
                seconds = existing_record.time_seconds % 60
                
                logger.info(f"[РЕКОРД] Существующий рекорд лучше: {existing_record.time_seconds} < {time_seconds}")
                response_data = {
                    'success': True,
                    'is_new_record': is_new_record,
                    'time_seconds': existing_record.time_seconds,
                    'time_formatted': f"{minutes:02d}:{seconds:02d}"
                }
                logger.info(f"[РЕКОРД] Отправка ответа с существующим рекордом: {response_data}")
                return JsonResponse(response_data)
        except Exception as e:
            logger.error(f"[РЕКОРД] Ошибка при работе с БД: {str(e)}", exc_info=True)
            return JsonResponse({'error': f'Ошибка при работе с БД: {str(e)}'}, status=500)
            
    except json.JSONDecodeError:
        logger.error("[РЕКОРД] Ошибка декодирования JSON")
        return JsonResponse({'error': 'Неверный формат данных'}, status=400)
    except Exception as e:
        logger.error(f"[РЕКОРД] Общая ошибка при сохранении рекорда: {str(e)}", exc_info=True)
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def module_match(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    cards = Card.objects.filter(module=module)
    
    # Получаем все термины из карточек и фильтруем только те, что состоят из одного слова
    all_terms = [(card.term, card.translation) for card in cards 
                 if card.term and card.translation and ' ' not in card.term.strip()]
    
    # Если нет терминов, показываем сообщение об ошибке
    if not all_terms:
        messages.error(request, 'В этом модуле нет слов для игры. Добавьте слова без пробелов.')
        return redirect('cards:module', module_id=module_id)

    # Если это GET запрос, показываем страницу выбора слов
    if request.method == 'GET':
        context = {
            'module': module,
            'terms': [{'term': term[0], 'translation': term[1]} for term in all_terms[:15]]
        }
        return render(request, 'cards/match_select.html', context)
    
    # Если это POST запрос, получаем выбранные слова
    selected_terms = request.POST.getlist('terms')
    print(f"Selected terms: {selected_terms}")  # Отладочная информация
    
    if not selected_terms:
        messages.error(request, 'Пожалуйста, выберите хотя бы одно слово для игры.')
        return redirect('cards:module_match', module_id=module_id)
    
    # Фильтруем и подготавливаем слова
    words = []
    term_mapping = {}  # Словарь для сопоставления русских терминов с английскими словами
    for term, translation in all_terms:
        if translation in selected_terms:  # Проверяем русский перевод
            # Убираем пробелы и приводим к верхнему регистру
            cleaned_word = ''.join(c for c in term.upper() if c.isalpha())
            if cleaned_word:
                words.append(cleaned_word)
                term_mapping[cleaned_word] = translation
    
    print(f"Prepared words: {words}")  # Отладочная информация
    
    if not words:
        messages.error(request, 'Не удалось подготовить слова для игры. Попробуйте выбрать другие слова.')
        return redirect('cards:module_match', module_id=module_id)

    # Параметры сетки
    grid_size = max(12, max((len(w) for w in words), default=0) + 2)
    grid = [['' for _ in range(grid_size)] for _ in range(grid_size)]
    directions = [
        (0, 1),   # горизонтально вправо
        (1, 0),   # вертикально вниз
        (1, 1),   # диагональ вправо вниз
        (-1, 1),  # диагональ вправо вверх
    ]
    
    # Сортируем слова по длине (сначала длинные)
    words.sort(key=len, reverse=True)
    placed_words = []
    
    # Пытаемся разместить слова ближе к центру и друг к другу
    center = grid_size // 2
    for word in words:
        placed = False
        attempts = 0
        best_position = None
        min_distance = float('inf')
        
        while not placed and attempts < 100:
            dir_idx = random.randint(0, len(directions)-1)
            dx, dy = directions[dir_idx]
            
            # Пытаемся разместить слово ближе к центру или к уже размещенным словам
            for x in range(grid_size):
                for y in range(grid_size):
                    if len(placed_words) == 0:
                        # Для первого слова - ближе к центру
                        distance = abs(x - center) + abs(y - center)
                    else:
                        # Для остальных слов - ближе к уже размещенным
                        distance = min(abs(x - px) + abs(y - py) 
                                    for w in placed_words 
                                    for px, py in [(w['start'][0] + i * w['direction'][0], 
                                                  w['start'][1] + i * w['direction'][1]) 
                                                 for i in range(len(w['word']))])
                    
                    # Проверяем, можно ли разместить слово
                    can_place = True
                    for i in range(len(word)):
                        xi = x + dx * i
                        yi = y + dy * i
                        if not (0 <= xi < grid_size and 0 <= yi < grid_size):
                            can_place = False
                            break
                        if grid[xi][yi] not in ('', word[i]):
                            can_place = False
                            break
                    
                    if can_place and distance < min_distance:
                        min_distance = distance
                        best_position = (x, y, dx, dy)
            
            if best_position:
                x, y, dx, dy = best_position
                for i in range(len(word)):
                    xi = x + dx * i
                    yi = y + dy * i
                    grid[xi][yi] = word[i]
                placed = True
                placed_words.append({
                    'word': word,
                    'start': [x, y],
                    'direction': [dx, dy],
                    'original': term_mapping[word]
                })
            
            attempts += 1
        
        if not placed:
            messages.warning(request, f'Не удалось разместить слово "{word}" на сетке.')
    
    if not placed_words:
        messages.error(request, 'Не удалось создать игровое поле. Попробуйте еще раз.')
        return redirect('cards:module_match', module_id=module_id)
    
    # Заполняем пустые клетки случайными английскими буквами
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    for i in range(grid_size):
        for j in range(grid_size):
            if grid[i][j] == '':
                grid[i][j] = random.choice(alphabet)
    
    # Создаем списки для итерации в шаблоне
    range_grid_size = range(grid_size)
    
    context = {
        'module': module,
        'words': [w['original'] for w in placed_words],  # Передаем русские термины
        'grid': grid,
        'grid_size': grid_size,
        'range_grid_size': range_grid_size,
        'placed_words': placed_words
    }
    
    return render(request, 'cards/match.html', context)

@login_required
@require_http_methods(["GET"])
def get_folder(request, folder_id):
    try:
        folder = get_object_or_404(Folder, id=folder_id, user=request.user)
        
        return JsonResponse({
            'id': folder.id,
            'name': folder.name,
            'parent_id': folder.parent.id if folder.parent else None
        })
    except Exception as e:
        logger.error(f"Error getting folder info for {folder_id}: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)

@login_required
def balloon_game(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    cards = Card.objects.filter(module=module)
    
    # Проверяем, является ли пользователь владельцем модуля
    is_owner = module.user == request.user
    
    context = {
        'module': module,
        'cards': cards,
        'is_owner': is_owner,
    }
    
    return render(request, 'cards/balloon_game.html', context)

@login_required
def get_balloon_game_record(request, module_id):
    module = get_object_or_404(Module, id=module_id)
    
    try:
        record = BalloonGameRecord.objects.get(user=request.user, module=module)
        return JsonResponse({'record': record.score})
    except BalloonGameRecord.DoesNotExist:
        return JsonResponse({'record': 0})

@login_required
def save_balloon_game_record(request, module_id):
    if request.method == 'POST':
        module = get_object_or_404(Module, id=module_id)
        data = json.loads(request.body)
        score = data.get('score', 0)
        difficulty = data.get('difficulty', 'easy')  # Получаем уровень сложности
        
        # Проверяем, существует ли уже рекорд
        record, created = BalloonGameRecord.objects.get_or_create(
            user=request.user,
            module=module,
            defaults={'score': score}
        )
        
        # Если рекорд уже существует, обновляем его только если новый результат лучше
        if not created and score > record.score:
            record.score = score
            record.save()
            
        return JsonResponse({'success': True, 'record': record.score})
    
    return JsonResponse({'success': False, 'error': 'Invalid request'})

@login_required
def balloon_game_leaderboard(request, module_id):
    """API для получения таблицы лидеров игры 'Воздушные шары'"""
    module = get_object_or_404(Module, id=module_id)
    
    # Получаем TOP-10 рекордов для данного модуля
    leaderboard = BalloonGameRecord.objects.filter(module=module) \
        .order_by('-score')[:10] \
        .select_related('user')
    
    # Формируем данные для таблицы лидеров
    leaderboard_data = []
    current_user_in_top = False
    
    for record in leaderboard:
        is_current_user = record.user == request.user
        if is_current_user:
            current_user_in_top = True
            
        leaderboard_data.append({
            'username': record.user.username,
            'score': record.score,
            'is_current_user': is_current_user
        })
    
    # Если текущего пользователя нет в топе, добавляем его рекорд в конец
    if not current_user_in_top:
        try:
            user_record = BalloonGameRecord.objects.get(
                user=request.user,
                module=module
            )
            
            # Получаем позицию пользователя в общем рейтинге
            user_position = BalloonGameRecord.objects.filter(
                module=module,
                score__gt=user_record.score
            ).count() + 1
            
            leaderboard_data.append({
                'username': f"{request.user.username} (ваш рекорд, #{user_position})",
                'score': user_record.score,
                'is_current_user': True
            })
        except BalloonGameRecord.DoesNotExist:
            # У пользователя еще нет рекорда
            pass
    
    return JsonResponse({'leaderboard': leaderboard_data})

@login_required
def ai_training(request, module_id):
    logger.info(f"Начало функции ai_training для модуля {module_id}")
    module = get_object_or_404(Module, id=module_id)
    cards = Card.objects.filter(module=module)
    sentences = []
    selected_level = None

    if request.method == 'POST':
        logger.info("Получен POST запрос.")
        try:
            selected_words_data_raw = request.POST.get('selected_words_data', '[]')
            logger.info(f"Получены сырые данные selected_words_data: {selected_words_data_raw}")
            selected_words_data = json.loads(selected_words_data_raw)
            logger.info(f"Распарсенные selected_words_data: {selected_words_data}")
            selected_level = request.POST.get('level') or 'A1'
            logger.info(f"Выбранный уровень: {selected_level}")
            
            if not selected_words_data:
                logger.warning("selected_words_data пуст после парсинга.")
                messages.warning(request, 'Пожалуйста, выберите слова для тренировки.')
                # Возможно, стоит рендерить страницу с пустым списком предложений, но без ошибки
                return render(request, 'cards/ai_training.html', {
                    'module': module,
                    'cards': cards,
                    'sentences': [] # Отправляем пустой список
                })

            # Инициализация клиента Mistral AI
            api_key = os.getenv('MISTRAL_API_KEY')
            if not api_key:
                logger.error("MISTRAL_API_KEY не установлен в .env файле.")
                messages.error(request, 'Ошибка конфигурации: API ключ Mistral AI не найден.')
                return render(request, 'cards/ai_training.html', {
                    'module': module,
                    'cards': cards,
                    'sentences': []
                })

            client = MistralClient(api_key=api_key)
            logger.info("Клиент Mistral AI инициализирован.")
            
            for word_data in selected_words_data:
                card_id = word_data.get('card_id')
                sentence_count = word_data.get('sentence_count')

                if not card_id or not sentence_count:
                    logger.warning(f"Пропущены данные для слова: card_id={card_id}, sentence_count={sentence_count}")
                    messages.warning(request, 'Некорректные данные для одного из слов.')
                    continue

                try:
                    card = get_object_or_404(Card, id=card_id)
                    logger.info(f"Обработка слова: {card.term} (ID: {card_id}), количество предложений: {sentence_count}")

                    # Формируем промпт для Mistral AI с учетом уровня CEFR
                    prompt = f"""Ты – генератор учебных предложений для изучения языка. 
Уровень сложности по CEFR: {selected_level}.
Сгенерируй {sentence_count} предложений на русском языке, обязательно используя слово '{card.term}' ({card.translation}).
Требования к предложениям:
- длина, лексика и грамматика соответствуют уровню {selected_level};
- 1 предложение = 1 смысл, без сложных конструкций (на низких уровнях), допускай более сложные структуры на уровнях C1–C2;
- избегай редких слов и идиом ниже уровней C1–C2.
Формат ответа строго такой (на каждое предложение):
РУС: [предложение на русском]
ENG: [естественный перевод на английском]
---
"""

                    logger.info(f"Отправка запроса в Mistral AI для слова \'{card.term}\'")

                    chat_messages = [
                        ChatMessage(role="user", content=prompt)
                    ]
                    
                    try:
                        chat_response = client.chat(
                            model="mistral-tiny",
                            messages=chat_messages,
                            temperature=0.7 # Добавляем temperature для разнообразия
                        )
                        logger.info("Получен ответ от Mistral AI.")
                        
                        # Обрабатываем ответ
                        if hasattr(chat_response, 'choices') and chat_response.choices:
                            response_text = chat_response.choices[0].message.content
                            logger.info(f"Текст ответа от Mistral AI: {response_text[:200]}...") # Логируем часть ответа

                            # Надёжный парсинг блоков формата РУС:/ENG:/---
                            raw_blocks = [blk for blk in response_text.split('---') if blk.strip()]
                            parsed_for_word = []
                            for blk in raw_blocks:
                                lines = [ln.strip() for ln in blk.strip().split('\n') if ln.strip()]
                                ru_line = next((ln for ln in lines if ln.upper().startswith('РУС:')), None)
                                en_line = next((ln for ln in lines if ln.upper().startswith('ENG:')), None)
                                if ru_line and en_line:
                                    russian = ru_line.split(':', 1)[1].strip()
                                    english = en_line.split(':', 1)[1].strip()
                                    if russian and english:
                                        parsed_for_word.append({'russian': russian, 'english': english})

                            # Обрезаем до запрошенного количества
                            trimmed = parsed_for_word[: int(sentence_count)]
                            sentences.extend(trimmed)
                            logger.info(
                                f"Сгенерировано {len(parsed_for_word)}, взято {len(trimmed)} из {sentence_count} для слова '{card.term}'. Итого предложений: {len(sentences)}"
                            )
                        else:
                             logger.warning(f"Ответ Mistral AI для слова \'{card.term}\' не содержит choices или choices пуст.")
                             messages.warning(request, f'Не удалось получить предложения для слова "{card.term}".')

                    except Exception as e:
                        logger.error(f"Ошибка при обращении к Mistral AI API для слова \'{card.term}\': {str(e)}", exc_info=True)
                        messages.error(request, f'Ошибка при генерации предложений для слова "{card.term}": {str(e)}')
                        # Продолжаем обрабатывать другие слова
                        continue

                except Card.DoesNotExist:
                     logger.warning(f"Карточка с ID {card_id} не найдена.")
                     messages.warning(request, f'Карточка с ID {card_id} не найдена.')
                     continue
                except Exception as e:
                    logger.error(f"Непредвиденная ошибка при обработке слова {card_id}: {str(e)}", exc_info=True)
                    messages.error(request, f'Произошла ошибка при обработке слова (ID: {card_id}): {str(e)}')
                    continue
            
            logger.info(f"Завершение обработки POST запроса. Сгенерировано всего предложений: {len(sentences)}")

        except json.JSONDecodeError:
            logger.error("Ошибка декодирования JSON в selected_words_data.", exc_info=True)
            messages.error(request, 'Ошибка данных: Неверный формат выбранных слов.')
        except Exception as e:
            logger.error(f"Общая ошибка при обработке POST запроса в ai_training: {str(e)}", exc_info=True)
            messages.error(request, f'Произошла общая ошибка при обработке запроса: {str(e)}')
    else:
        logger.info("Получен GET запрос.")

    # Логируем количество предложений перед рендерингом
    logger.info(f"Рендеринг шаблона. Количество предложений для отображения: {len(sentences)}")

    # Если это POST и есть предложения — показываем страницу с заданиями,
    # иначе — страницу выбора слов/настроек
    if request.method == 'POST' and sentences:
        return render(request, 'cards/ai_training_session.html', {
            'module': module,
            'sentences': sentences,
            'level': selected_level or 'A1'
        })
    else:
        return render(request, 'cards/ai_training.html', {
            'module': module,
            'cards': cards,
            'sentences': sentences,
            'level': selected_level or 'A1'
        })



@login_required
def sidebar_chat(request):
    # Получаем последние сообщения активного чата для истории
    ai_chat = AIChat.objects.filter(user=request.user, is_active=True).first()
    messages = []
    if ai_chat:
        messages = ai_chat.ai_messages.order_by('created_at')[:50]  # последние 50 сообщений
    
    context = {
        'chat_messages': messages,
        'user': request.user,
    }
    return render(request, 'cards/sidebar_chat.html', context)


@login_required
@require_POST
def api_chat_ai(request):
    try:
        # Обработка текстового сообщения
        data = json.loads(request.body.decode('utf-8'))
        user_message = (data.get('message') or '').strip()
        if not user_message:
            return JsonResponse({'error': 'Пустое сообщение'}, status=400)

        # Получаем или создаем активный AI чат для пользователя
        ai_chat = AIChat.objects.filter(user=request.user, is_active=True).first()
        if not ai_chat:
            ai_chat = AIChat.objects.create(
                user=request.user,
                title=f"English Practice - {time.strftime('%Y-%m-%d %H:%M')}"
            )
        
        # Сохраняем сообщение пользователя
        user_msg = AIMessage.objects.create(
            ai_chat=ai_chat,
            sender_type='user',
            content=user_message
        )

        api_key = os.getenv('MISTRAL_API_KEY')
        if not api_key:
            return JsonResponse({'error': 'AI не настроен'}, status=500)

        # Промпт: человеческий разговор + мнение + вопрос + JSON с анализом ошибок
        modern_prompt = (
            "You are a friendly English tutor. You MUST respond with ONLY valid JSON in this exact format:\n"
            "{\n"
            "  \"reply\": \"your natural English response with opinion and a follow-up question\",\n"
            "  \"russian_translation\": \"proper russian translation of your reply\",\n"
            "  \"analysis\": {\n"
            "    \"errors\": [\"error description 1\", \"error description 2\"],\n"
            "    \"suggestion\": \"corrected version of the sentence\",\n"
            "    \"topics\": [\"Grammar topic 1\", \"Vocabulary topic 2\"]\n"
            "  }\n"
            "}\n\n"
            "CRITICAL RULES:\n"
            "1. Respond with ONLY the JSON above, no other text, no explanations\n"
            "2. The 'errors' field must be an array of strings, each error as a separate string\n"
            "3. Each error should be one string like: \"'I like buy' should be 'I like to buy'\" or \"'He go' should be 'He goes'\"\n"
            "4. Find ALL grammatical errors including:\n"
            "   - 'I am went' → 'I went' (wrong auxiliary with past tense)\n"
            "   - 'I am go' → 'I go' or 'I am going'\n"
            "   - 'I like buy' → 'I like to buy' (missing infinitive marker)\n"
            "   - 'He go' → 'He goes' (subject-verb disagreement)\n"
            "   - Missing articles: 'I have car' → 'I have a car'\n"
            "   - Wrong prepositions: 'I go in school' → 'I go to school'\n"
            "   - Double negatives: 'I don't have nothing' → 'I don't have anything'\n"
            "   - Spelling mistakes: 'scool' → 'school'\n"
            "   - Wrong word choice: 'prison' → 'example'\n"
            "   - Word order mistakes\n"
            "5. If no errors found, use empty array: \"errors\": []\n"
            "6. Always include a follow-up question in your reply\n"
            "7. Be thorough - check every word for mistakes\n"
            "8. NEVER add any text before or after the JSON\n"
            "9. Make sure russian_translation is proper Russian, not mixed with English\n"
            "10. Each error in the errors array must be a separate string, not combined\n"
            "11. Do NOT include explanations or corrections in the reply field - only natural conversation\n"
            "12. The reply should be conversational, not instructional\n"
            "13. Example of correct errors array: [\"'I like buy' should be 'I like to buy'\"]\n"
            "14. The 'topics' field should list grammar/vocabulary topics to review based on errors found\n"
            "15. Topics examples: 'Infinitives with TO', 'Present Simple (3rd person)', 'Articles (a/an/the)', 'Prepositions', 'Past Tense', 'Word Order', etc.\n"
            "16. If no errors, use empty topics array: \"topics\": []\n"
            "17. Topics should be in English, concise (2-4 words), and specific to the errors found"
        )
        
        start_time = time.time()
        client = MistralClient(api_key=api_key)
        chat_messages = [
            ChatMessage(role="system", content=modern_prompt),
            ChatMessage(role="user", content=user_message)
        ]
        resp = client.chat(model="mistral-small", messages=chat_messages, temperature=0.7)
        raw_reply = resp.choices[0].message.content if getattr(resp, 'choices', None) else '{"reply":"Sorry, a glitch happened.","russian_translation":"Извини, произошел сбой.","analysis":{"errors":[],"suggestion":"","topics":[]}}'
        response_time = int((time.time() - start_time) * 1000)
        
        # Очищаем от markdown блоков если они есть (```json ... ```)
        clean_reply = raw_reply.strip()
        if clean_reply.startswith('```'):
            # Удаляем ```json или ``` в начале
            lines = clean_reply.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            # Удаляем ``` в конце
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            clean_reply = '\n'.join(lines).strip()
        
        # Пытаемся распарсить JSON
        reply = ""
        russian_translation = None
        analysis = {"errors": [], "suggestion": "", "topics": []}
        try:
            parsed = json.loads(clean_reply)
            reply = (parsed.get("reply") or "").strip()
            russian_translation = (parsed.get("russian_translation") or None)
            analysis_obj = parsed.get("analysis") or {}
            errors = analysis_obj.get("errors") or []
            suggestion = analysis_obj.get("suggestion") or ""
            topics = analysis_obj.get("topics") or []
            analysis = {"errors": errors, "suggestion": suggestion, "topics": topics}
        except Exception as parse_err:
            logger.warning(f"Failed to parse AI response as JSON: {parse_err}. Raw: {raw_reply[:200]}")
            reply = clean_reply
            russian_translation = None
            analysis = {"errors": [], "suggestion": "", "topics": []}
        
        # Сохраняем ответ ИИ
        ai_msg = AIMessage.objects.create(
            ai_chat=ai_chat,
            sender_type='ai',
            content=reply,
            ai_model='mistral-small',
            ai_prompt_used=modern_prompt,
            response_time_ms=response_time
        )
        
        return JsonResponse({
            'reply': reply,
            'russian_translation': russian_translation,
            'analysis': analysis,
            'user_text': user_message  # Включаем распознанный текст для аудио
        })
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат JSON'}, status=400)
    except Exception as e:
        logger.error(f"Ошибка api_chat_ai: {e}")
        return JsonResponse({'error': 'Серверная ошибка'}, status=500)


@login_required
@require_POST
def api_translate_message(request):
    """
    API для перевода сообщений через Google Translate
    """
    try:
        # Проверяем доступность googletrans
        try:
            from googletrans import Translator
            TRANSLATION_AVAILABLE = True
        except ImportError:
            TRANSLATION_AVAILABLE = False
        
        data = json.loads(request.body.decode('utf-8'))
        message = (data.get('message') or '').strip()
        target_language = data.get('target_language', 'ru')
        
        if not message:
            return JsonResponse({'error': 'Пустое сообщение'}, status=400)
        
        if not TRANSLATION_AVAILABLE:
            return JsonResponse({
                'original': message,
                'translated': '[Перевод недоступен - не установлен googletrans]',
                'source_language': 'unknown',
                'target_language': target_language,
                'status': 'warning'
            })
        
        translator = Translator()
        detection = translator.detect(message)
        source_lang = detection.lang
        translation = translator.translate(message, src=source_lang, dest=target_language)
        
        return JsonResponse({
            'original': message,
            'translated': translation.text,
            'source_language': source_lang,
            'target_language': target_language,
            'status': 'success'
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат JSON'}, status=400)
    except Exception as e:
        logger.error(f"Ошибка перевода: {e}")
        return JsonResponse({'error': 'Ошибка перевода'}, status=500)


@login_required
@require_POST
def api_clear_ai_chat(request):
    """
    API для очистки истории AI чата
    """
    try:
        # Находим активный AI чат пользователя
        ai_chat = AIChat.objects.filter(user=request.user, is_active=True).first()
        
        if ai_chat:
            # Удаляем все сообщения в чате
            ai_chat.ai_messages.all().delete()
            
            # Делаем чат неактивным и создаем новый
            ai_chat.is_active = False
            ai_chat.save()
            
            # Создаем новый чат
            new_chat = AIChat.objects.create(
                user=request.user,
                title=f"New English Practice - {time.strftime('%Y-%m-%d %H:%M')}"
            )
            
            return JsonResponse({
                'message': 'Chat cleared successfully',
                'status': 'success',
                'new_chat_id': new_chat.id
            })
        else:
            return JsonResponse({
                'message': 'No active chat found',
                'status': 'success'
            })
        
    except Exception as e:
        logger.error(f"Ошибка очистки чата: {e}")
        return JsonResponse({'error': 'Ошибка очистки чата'}, status=500)


@login_required
@require_http_methods(["POST"])
def api_tts(request):
    try:
        data = json.loads(request.body.decode('utf-8'))
        text = (data.get('text') or '').strip()
        force_provider = (data.get('provider') or 'auto').strip().lower()
        override_voice = (data.get('voice') or '').strip() or None
        voice_type = (data.get('voice_type') or 'female').strip().lower()  # 'female' or 'male'
        lang = (data.get('lang') or 'en-US').strip()  # Язык для озвучки
        
        logger.info(f"TTS request: text_length={len(text)}, voice_type={voice_type}, lang={lang}, provider={force_provider}")
        
        if not text:
            return JsonResponse({'error': 'Пустой текст'}, status=400)
        
        # Путь сохранения
        file_name = f"tts_{int(time.time()*1000)}.mp3"
        rel_path = os.path.join('audio', file_name)
        abs_dir = os.path.join(getattr(settings, 'MEDIA_ROOT', os.path.join('media')), 'audio')
        os.makedirs(abs_dir, exist_ok=True)
        abs_path = os.path.join(abs_dir, file_name)

        # Выбираем качественные английские Edge TTS голоса
        if lang.startswith('en'):
            if override_voice:
                preferred_voice = override_voice
            elif voice_type == 'male':
                # Лучшие мужские английские голоса Edge TTS
                preferred_voice = 'en-US-GuyNeural'  # Очень естественный и приятный
                logger.info(f"✅ TTS: Selected MALE voice: {preferred_voice} (voice_type={voice_type})")
            elif voice_type == 'female':
                # Лучшие женские английские голоса Edge TTS
                preferred_voice = 'en-US-AriaNeural'  # Очень естественный и приятный
                logger.info(f"✅ TTS: Selected FEMALE voice: {preferred_voice} (voice_type={voice_type})")
            else:
                # По умолчанию женский голос, если voice_type не распознан
                preferred_voice = 'en-US-AriaNeural'
                logger.warning(f"⚠️ TTS: Unknown voice_type '{voice_type}', using default FEMALE voice: {preferred_voice}")
        else:
            # Для других языков используем старую логику
            preferred_voice = override_voice or os.getenv('TTS_VOICE', 'ru-RU-SvetlanaNeural')
        azure_key = os.getenv('AZURE_TTS_KEY')
        azure_region = os.getenv('AZURE_TTS_REGION')
        azure_voice = os.getenv('AZURE_TTS_VOICE', preferred_voice)

        def save_bytes_to_mp3(data_bytes: bytes, target_path: str):
            with open(target_path, 'wb') as f:
                f.write(data_bytes)

        # 0) ElevenLabs (если указан ключ и VOICE_ID) — очень натуральная озвучка
        el_key = os.getenv('ELEVENLABS_API_KEY')
        el_voice = os.getenv('ELEVENLABS_VOICE_ID')
        if (force_provider in ('auto','elevenlabs')) and el_key and (override_voice or el_voice):
            try:
                el_url = f"https://api.elevenlabs.io/v1/text-to-speech/{override_voice or el_voice}"
                payload = {
                    "text": text,
                    "model_id": os.getenv('ELEVENLABS_MODEL_ID', 'eleven_multilingual_v2'),
                    "voice_settings": {
                        "stability": float(os.getenv('ELEVENLABS_STABILITY', '0.4')),
                        "similarity_boost": float(os.getenv('ELEVENLABS_SIMILARITY', '0.8')),
                        "style": float(os.getenv('ELEVENLABS_STYLE', '0.3')),
                        "use_speaker_boost": True
                    }
                }
                headers = {
                    'xi-api-key': el_key,
                    'Content-Type': 'application/json'
                }
                resp = requests.post(el_url, headers=headers, json=payload, timeout=30)
                if resp.status_code == 200 and resp.content:
                    save_bytes_to_mp3(resp.content, abs_path)
                    media_url = getattr(settings, 'MEDIA_URL', '/media/')
                    return JsonResponse({'url': f"{media_url}{rel_path}"})
                else:
                    logger.warning("ElevenLabs TTS error: %s %s", resp.status_code, resp.text[:200])
            except Exception as el_err:
                logger.warning("ElevenLabs TTS failed, try Azure/Edge/gTTS. Error: %s", el_err, exc_info=False)

        # 1) Пытаемся использовать Azure Neural TTS, если заданы ключ и регион (наиболее естественный)
        if (force_provider in ('auto','azure')) and azure_key and azure_region:
            try:
                synth_url = f"https://{azure_region}.tts.speech.microsoft.com/cognitiveservices/v1"
                # Natural style SSML
                ssml = f"""
<speak version='1.0' xml:lang='ru-RU'>
  <voice xml:lang='ru-RU' name='{azure_voice}'>
    <mstts:express-as style='general' styledegree='1'>
      <prosody rate='-5%' pitch='+2%'> {text} </prosody>
    </mstts:express-as>
  </voice>
</speak>
""".strip()
                headers = {
                    'Ocp-Apim-Subscription-Key': azure_key,
                    'Content-Type': 'application/ssml+xml',
                    'X-Microsoft-OutputFormat': 'audio-48khz-192kbitrate-mono-mp3'
                }
                resp = requests.post(synth_url, data=ssml.encode('utf-8'), headers=headers, timeout=20)
                if resp.status_code == 200 and resp.content:
                    save_bytes_to_mp3(resp.content, abs_path)
                else:
                    raise RuntimeError(f"Azure TTS error: {resp.status_code} {resp.text[:200]}")
            except Exception as az_err:
                logger.warning("Azure TTS failed, try Edge/gTTS. Error: %s", az_err, exc_info=False)
                # 2) Пробуем Edge TTS (без ключей)
                if edge_tts is not None:
                    try:
                        async def synth_edge():
                            # Для английского используем более естественные параметры
                            if lang.startswith('en'):
                                if voice_type == 'male':
                                    rate = "-4%"
                                    pitch = "-2%"
                                else:  # female
                                    rate = "-3%"
                                    pitch = "+5%"
                            else:
                                rate = "-5%"
                                pitch = "+2%"
                            logger.info(f"TTS: voice={preferred_voice}, type={voice_type}, rate={rate}, pitch={pitch}")
                            communicator = edge_tts.Communicate(text, preferred_voice, rate=rate, pitch=pitch)
                            await communicator.save(abs_path)
                        asyncio.run(synth_edge())
                    except Exception as edge_err:
                        logger.warning("Edge TTS failed, fallback gTTS. Error: %s", edge_err, exc_info=False)
                        tts_lang = 'en' if lang.startswith('en') else 'ru'
                        tts = gTTS(text=text, lang=tts_lang, slow=False)
                        tts.save(abs_path)
                else:
                    tts_lang = 'en' if lang.startswith('en') else 'ru'
                    tts = gTTS(text=text, lang=tts_lang, slow=False)
                    tts.save(abs_path)
        else:
            # 2) Если Azure нет — сначала Edge (приоритет для английского), затем gTTS
            if (force_provider in ('auto','edge')) and edge_tts is not None:
                try:
                    async def synth_edge():
                        # Для английского используем более естественные параметры
                        if lang.startswith('en'):
                            if voice_type == 'male':
                                rate = "-4%"
                                pitch = "-2%"
                            else:  # female
                                rate = "-3%"
                                pitch = "+5%"
                        else:
                            rate = "-5%"
                            pitch = "+2%"
                        logger.info(f"🎤 TTS synthesis: voice={preferred_voice}, type={voice_type}, rate={rate}, pitch={pitch}, text_length={len(text)}")
                        communicator = edge_tts.Communicate(text, preferred_voice, rate=rate, pitch=pitch)
                        await communicator.save(abs_path)
                        logger.info(f"✅ TTS file saved: {abs_path}")
                    asyncio.run(synth_edge())
                except Exception as edge_err:
                    logger.warning("Edge TTS failed, fallback gTTS. Error: %s", edge_err, exc_info=False)
                    tts_lang = 'en' if lang.startswith('en') else 'ru'
                    tts = gTTS(text=text, lang=tts_lang, slow=False)
                    tts.save(abs_path)
            else:
                tts_lang = 'en' if lang.startswith('en') else 'ru'
                tts = gTTS(text=text, lang=tts_lang, slow=False)
                tts.save(abs_path)

        media_url = getattr(settings, 'MEDIA_URL', '/media/')
        return JsonResponse({'url': f"{media_url}{rel_path}"})
    except Exception as e:
        logger.error(f"Ошибка api_tts: {e}")
        return JsonResponse({'error': 'Серверная ошибка'}, status=500)


@login_required
@require_http_methods(["POST"])
def api_asr(request):
    try:
        if 'audio' not in request.FILES:
            logger.warning("api_asr: audio file not in request.FILES")
            return JsonResponse({'error': 'Файл audio не передан'}, status=400)

        audio_file = request.FILES['audio']
        logger.info(f"api_asr: received audio file, size: {audio_file.size}, name: {audio_file.name}, content_type: {audio_file.content_type}")
        
        if audio_file.size == 0:
            logger.warning("api_asr: audio file is empty")
            return JsonResponse({'error': 'Файл аудио пуст'}, status=400)
        
        # Определяем расширение файла
        file_ext = '.webm'
        if audio_file.name:
            if '.mp4' in audio_file.name.lower():
                file_ext = '.mp4'
            elif '.ogg' in audio_file.name.lower():
                file_ext = '.ogg'
        elif audio_file.content_type:
            if 'mp4' in audio_file.content_type:
                file_ext = '.mp4'
            elif 'ogg' in audio_file.content_type:
                file_ext = '.ogg'
        
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=file_ext)
        try:
            with os.fdopen(tmp_fd, 'wb') as tmp:
                for chunk in audio_file.chunks():
                    tmp.write(chunk)
            
            logger.info(f"api_asr: saved audio to {tmp_path}, size: {os.path.getsize(tmp_path)} bytes")

            model = _get_whisper_model()
            if model is None:
                logger.error("api_asr: Whisper model is not available")
                return JsonResponse({'error': 'ASR не доступен на сервере. Убедитесь, что faster-whisper установлен.'}, status=501)

            logger.info("api_asr: starting transcription")
            # Transcribe
            segments, info = model.transcribe(tmp_path, vad_filter=True, language='en')
            text_parts = []
            for seg in segments:
                if getattr(seg, 'text', None):
                    text_parts.append(seg.text.strip())
            text = ' '.join(text_parts).strip()
            
            logger.info(f"api_asr: transcription completed, text length: {len(text)}")
            if not text:
                logger.warning("api_asr: transcription returned empty text")
                return JsonResponse({'error': 'Не удалось распознать речь. Попробуйте говорить громче и четче.'}, status=400)
            
            return JsonResponse({'text': text})
        finally:
            try:
                os.remove(tmp_path)
            except Exception as e:
                logger.warning(f"api_asr: failed to remove temp file {tmp_path}: {e}")
    except Exception as e:
        logger.error(f"Ошибка api_asr: {e}", exc_info=True)
        return JsonResponse({'error': f'Серверная ошибка: {str(e)}'}, status=500)


@login_required
@require_POST
def api_conversation_analytics(request):
    """
    API для получения аналитики разговора пользователя
    """
    try:
        # Получаем активный чат пользователя
        ai_chat = AIChat.objects.filter(user=request.user, is_active=True).first()
        
        if not ai_chat:
            return JsonResponse({'error': 'Нет активного разговора для анализа'}, status=400)
        
        # Получаем сообщения пользователя
        user_messages = ai_chat.ai_messages.filter(sender_type='user').order_by('created_at')
        
        if user_messages.count() < 3:
            return JsonResponse({'error': 'Недостаточно сообщений для анализа (минимум 3)'}, status=400)
        
        # Собираем текст сообщений
        conversation_text = '\n'.join([msg.content for msg in user_messages[:20]])  # Последние 20 сообщений
        
        api_key = os.getenv('MISTRAL_API_KEY')
        if not api_key:
            return JsonResponse({'error': 'AI не настроен'}, status=500)
        
        # Промпт для анализа разговора
        analytics_prompt = (
            "You are an English language expert evaluating a student's conversation. "
            "Analyze the following messages from the student and provide scores from 1 to 10 for each metric.\n\n"
            "You MUST respond with ONLY valid JSON in this exact format:\n"
            "{\n"
            "  \"accuracy\": 8,\n"
            "  \"grammar\": 7,\n"
            "  \"vocabulary\": 9,\n"
            "  \"topic_development\": 6,\n"
            "  \"feedback\": \"Brief feedback in Russian (2-3 sentences)\"\n"
            "}\n\n"
            "SCORING CRITERIA:\n"
            "1. Accuracy (1-10): Overall correctness of language use, pronunciation patterns visible in text\n"
            "2. Grammar (1-10): Correct use of tenses, articles, sentence structure, verb forms\n"
            "3. Vocabulary (1-10): Range and appropriateness of words used, variety of expressions\n"
            "4. Topic Development (1-10): Ability to develop ideas, provide details, maintain conversation flow\n\n"
            "SCORING SCALE:\n"
            "1-3: Poor/Many errors\n"
            "4-6: Average/Some errors\n"
            "7-8: Good/Few errors\n"
            "9-10: Excellent/Almost perfect\n\n"
            "IMPORTANT:\n"
            "- Respond ONLY with JSON, no other text\n"
            "- Feedback must be in Russian, encouraging but honest\n"
            "- Be fair but motivating in your assessment\n"
            "- Consider the overall pattern, not just individual mistakes"
        )
        
        client = MistralClient(api_key=api_key)
        chat_messages = [
            ChatMessage(role="system", content=analytics_prompt),
            ChatMessage(role="user", content=f"Student's messages:\n{conversation_text}")
        ]
        
        resp = client.chat(model="mistral-small", messages=chat_messages, temperature=0.3)
        raw_reply = resp.choices[0].message.content if getattr(resp, 'choices', None) else '{"accuracy":5,"grammar":5,"vocabulary":5,"topic_development":5,"feedback":"Не удалось проанализировать"}'
        
        # Очищаем от markdown
        clean_reply = raw_reply.strip()
        if clean_reply.startswith('```'):
            lines = clean_reply.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            clean_reply = '\n'.join(lines).strip()
        
        # Парсим JSON
        try:
            analytics_data = json.loads(clean_reply)
            return JsonResponse({
                'accuracy': min(max(int(analytics_data.get('accuracy', 5)), 1), 10),
                'grammar': min(max(int(analytics_data.get('grammar', 5)), 1), 10),
                'vocabulary': min(max(int(analytics_data.get('vocabulary', 5)), 1), 10),
                'topic_development': min(max(int(analytics_data.get('topic_development', 5)), 1), 10),
                'feedback': analytics_data.get('feedback', 'Продолжайте практиковаться!')
            })
        except Exception as parse_err:
            logger.warning(f"Failed to parse analytics: {parse_err}. Raw: {raw_reply[:200]}")
            return JsonResponse({
                'accuracy': 5,
                'grammar': 5,
                'vocabulary': 5,
                'topic_development': 5,
                'feedback': 'Не удалось проанализировать разговор. Попробуйте позже.'
            })
        
    except Exception as e:
        logger.error(f"Ошибка api_conversation_analytics: {e}")
        return JsonResponse({'error': 'Серверная ошибка'}, status=500)


@login_required
@require_http_methods(["GET"])
def media_feed(request):
    """
    Возвращает подборку англоязычного контента (фильмы, сериалы, мультфильмы)
    с TMDB API (The Movie Database).
    """
    category = (request.GET.get('category') or 'movies').lower()
    tmdb_api_key = os.getenv('TMDB_API_KEY', '')
    
    # Если нет API ключа, используем публичный доступ (ограниченный)
    if not tmdb_api_key:
        tmdb_api_key = '1f54bd990f1cdfb230adb312546d765d'  # Публичный ключ для демо
    
    base_url = 'https://api.themoviedb.org/3'
    headers = {'accept': 'application/json'}
    
    items = []
    
    try:
        if category == 'movies':
            # Популярные фильмы
            url = f'{base_url}/movie/popular'
            params = {'api_key': tmdb_api_key, 'language': 'en-US', 'page': 1}
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            for movie in data.get('results', [])[:20]:
                if movie.get('original_language') != 'en':
                    continue
                
                poster_path = movie.get('poster_path')
                backdrop_path = movie.get('backdrop_path')
                poster_url = f"https://image.tmdb.org/t/p/w500{poster_path}" if poster_path else None
                backdrop_url = f"https://image.tmdb.org/t/p/w1280{backdrop_path}" if backdrop_path else None
                
                overview = movie.get('overview', '')
                if len(overview) > 200:
                    overview = overview[:197] + '...'
                
                items.append({
                    'id': movie.get('id'),
                    'title': movie.get('title'),
                    'summary': overview,
                    'cover': poster_url,
                    'backdrop': backdrop_url,
                    'rating': round(movie.get('vote_average', 0), 1),
                    'genres': [],  # Жанры будут отображаться на странице детального просмотра
                    'release_date': movie.get('release_date'),
                    'type': 'movie',
                    'tmdb_id': movie.get('id')
                })
                
        elif category == 'series':
            # Популярные сериалы
            url = f'{base_url}/tv/popular'
            params = {'api_key': tmdb_api_key, 'language': 'en-US', 'page': 1}
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            for tv in data.get('results', [])[:20]:
                if tv.get('original_language') != 'en':
                    continue
                
                poster_path = tv.get('poster_path')
                backdrop_path = tv.get('backdrop_path')
                poster_url = f"https://image.tmdb.org/t/p/w500{poster_path}" if poster_path else None
                backdrop_url = f"https://image.tmdb.org/t/p/w1280{backdrop_path}" if backdrop_path else None
                
                overview = tv.get('overview', '')
                if len(overview) > 200:
                    overview = overview[:197] + '...'
                
                items.append({
                    'id': tv.get('id'),
                    'title': tv.get('name'),
                    'summary': overview,
                    'cover': poster_url,
                    'backdrop': backdrop_url,
                    'rating': round(tv.get('vote_average', 0), 1),
                    'genres': [],  # Жанры будут отображаться на странице детального просмотра
                    'release_date': tv.get('first_air_date'),
                    'type': 'tv',
                    'tmdb_id': tv.get('id')
                })
                
        elif category == 'cartoons':
            # Анимационные фильмы
            url = f'{base_url}/discover/movie'
            params = {
                'api_key': tmdb_api_key,
                'language': 'en-US',
                'with_genres': '16',  # Animation genre ID
                'page': 1
            }
            response = requests.get(url, params=params, headers=headers, timeout=10)
            response.raise_for_status()
            data = response.json()
            
            for movie in data.get('results', [])[:20]:
                if movie.get('original_language') != 'en':
                    continue
                
                poster_path = movie.get('poster_path')
                backdrop_path = movie.get('backdrop_path')
                poster_url = f"https://image.tmdb.org/t/p/w500{poster_path}" if poster_path else None
                backdrop_url = f"https://image.tmdb.org/t/p/w1280{backdrop_path}" if backdrop_path else None
                
                overview = movie.get('overview', '')
                if len(overview) > 200:
                    overview = overview[:197] + '...'
                
                items.append({
                    'id': movie.get('id'),
                    'title': movie.get('title'),
                    'summary': overview,
                    'cover': poster_url,
                    'backdrop': backdrop_url,
                    'rating': round(movie.get('vote_average', 0), 1),
                    'genres': [],  # Жанры будут отображаться на странице детального просмотра
                    'release_date': movie.get('release_date'),
                    'type': 'movie',
                    'tmdb_id': movie.get('id')
                })
                
        return JsonResponse({'items': items[:20]})
        
    except requests.RequestException as exc:
        logger.error(f"Media feed request failed ({category}): {exc}")
        return JsonResponse({'error': 'Не удалось загрузить подборку. Попробуйте позже.'}, status=502)

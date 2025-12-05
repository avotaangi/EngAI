from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from .models import TextCheck, Error, Theme
import json
import os
import time
import logging
from django.utils import timezone
from datetime import timedelta
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage

logger = logging.getLogger(__name__)

@login_required
def text_check_view(request):
    return render(request, 'text_check/text_check.html')

@login_required
def text_check_history(request):
    if request.method == 'GET':
        month_ago = timezone.now() - timedelta(days=31)
        history = TextCheck.objects.filter(user=request.user, created_at__gte=month_ago).order_by('-created_at')
        data = []
        
        for item in history:
            errors = Error.objects.filter(text_check=item).values('error_text', 'correction', 'error_type')
            themes = Theme.objects.filter(text_check=item).values('name', 'description')
            
            data.append({
                'original_text': item.original_text,
                'corrected_text': item.corrected_text,
                'created_at': item.created_at.strftime('%d.%m.%Y %H:%M'),
                'errors': list(errors),
                'themes': list(themes)
            })
            
        return JsonResponse({'status': 'success', 'history': data})
    return JsonResponse({'status': 'error', 'message': 'Method not allowed'}, status=405)

@login_required
def check_text(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            text = data.get('text', '').strip()
            
            if not text:
                return JsonResponse({
                    'status': 'error',
                    'message': 'Текст не может быть пустым'
                }, status=400)
            
            # Получаем API ключ
            api_key = os.getenv('MISTRAL_API_KEY')
            if not api_key:
                logger.error("MISTRAL_API_KEY не установлен")
                return JsonResponse({
                    'status': 'error',
                    'message': 'AI не настроен'
                }, status=500)
            
            # Создаем промпт для проверки текста
            text_check_prompt = (
                "You are an expert English grammar and spelling checker. "
                "Analyze the following English text and provide a comprehensive check. "
                "You MUST respond with ONLY valid JSON in this exact format:\n"
                "{\n"
                "  \"corrected_text\": \"the fully corrected version of the text\",\n"
                "  \"errors\": [\n"
                "    {\n"
                "      \"text\": \"the incorrect word/phrase\",\n"
                "      \"correction\": \"the correct word/phrase\",\n"
                "      \"type\": \"Grammar|Spelling|Punctuation|Vocabulary|Style\",\n"
                "      \"position\": approximate_character_position\n"
                "    }\n"
                "  ],\n"
                "  \"themes\": [\n"
                "    {\n"
                "      \"name\": \"Grammar topic name\",\n"
                "      \"description\": \"Brief description of what to review\"\n"
                "    }\n"
                "  ],\n"
                "  \"topics\": [\"topic1\", \"topic2\"]\n"
                "}\n\n"
                "CRITICAL RULES:\n"
                "1. Respond with ONLY the JSON above, no other text, no explanations\n"
                "2. Find ALL errors: grammar, spelling, punctuation, vocabulary, style\n"
                "3. The 'corrected_text' must be the full corrected version of the entire input text\n"
                "4. Each error must have:\n"
                "   - 'text': the exact incorrect word/phrase from the original\n"
                "   - 'correction': the correct replacement\n"
                "   - 'type': one of: Grammar, Spelling, Punctuation, Vocabulary, Style\n"
                "   - 'position': approximate character position (0-based index)\n"
                "5. If no errors found, use empty array: \"errors\": []\n"
                "6. 'themes' should list grammar/vocabulary topics to review based on errors found\n"
                "7. 'topics' should be a simple array of topic names (for word topics display)\n"
                "8. Topics should be in Russian, concise, and specific to the errors\n"
                "9. Examples of themes: {\"name\": \"Present Simple\", \"description\": \"Повторите правила использования настоящего простого времени\"}\n"
                "10. Examples of topics: [\"Путешествия\", \"Семья\", \"Работа\"]\n"
                "11. NEVER add any text before or after the JSON\n"
                "12. Make sure all JSON is valid and properly formatted\n"
            )
            
            # Вызываем Mistral AI
            start_time = time.time()
            client = MistralClient(api_key=api_key)
            chat_messages = [
                ChatMessage(role="system", content=text_check_prompt),
                ChatMessage(role="user", content=f"Please check this English text:\n\n{text}")
            ]
            
            try:
                resp = client.chat(
                    model="mistral-small",
                    messages=chat_messages,
                    temperature=0.3  # Lower temperature for more consistent grammar checking
                )
                raw_response = resp.choices[0].message.content if getattr(resp, 'choices', None) else None
                response_time = int((time.time() - start_time) * 1000)
                
                if not raw_response:
                    raise Exception("Empty response from AI")
                
                # Очищаем от markdown блоков если они есть
                clean_response = raw_response.strip()
                if clean_response.startswith('```'):
                    lines = clean_response.split('\n')
                    if lines[0].startswith('```'):
                        lines = lines[1:]
                    if lines and lines[-1].strip() == '```':
                        lines = lines[:-1]
                    clean_response = '\n'.join(lines).strip()
                
                # Парсим JSON ответ
                try:
                    parsed = json.loads(clean_response)
                except json.JSONDecodeError as e:
                    logger.error(f"Failed to parse AI response as JSON: {e}. Raw: {raw_response[:500]}")
                    # Fallback: создаем базовый ответ
                    parsed = {
                        "corrected_text": text,
                        "errors": [],
                        "themes": [],
                        "topics": []
                    }
                
                corrected_text = parsed.get("corrected_text", text)
                errors_data = parsed.get("errors", [])
                themes_data = parsed.get("themes", [])
                topics_data = parsed.get("topics", [])
                
                # Создаем запись TextCheck
                text_check = TextCheck.objects.create(
                    user=request.user,
                    original_text=text,
                    corrected_text=corrected_text
                )
                
                # Создаем записи об ошибках
                created_errors = []
                for error_data in errors_data:
                    error = Error.objects.create(
                        text_check=text_check,
                        error_text=error_data.get('text', ''),
                        correction=error_data.get('correction', ''),
                        error_type=error_data.get('type', 'Grammar'),
                        position=error_data.get('position', 0)
                    )
                    created_errors.append(error)
                
                # Создаем темы для повторения
                created_themes = []
                for theme_data in themes_data:
                    theme = Theme.objects.create(
                        text_check=text_check,
                        name=theme_data.get('name', ''),
                        description=theme_data.get('description', '')
                    )
                    # Связываем тему с ошибками соответствующего типа
                    for error in created_errors:
                        if error.error_type.lower() in theme.name.lower() or theme.name.lower() in error.error_type.lower():
                            theme.errors.add(error)
                    created_themes.append(theme)
                
                # Формируем ответ для фронтенда
                errors_response = [
                    {
                        'text': error.error_text,
                        'correction': error.correction,
                        'type': error.error_type,
                        'position': error.position
                    }
                    for error in created_errors
                ]
                
                themes_response = [
                    {
                        'name': theme.name,
                        'description': theme.description
                    }
                    for theme in created_themes
                ]
                
                return JsonResponse({
                    'status': 'success',
                    'original_text': text,
                    'corrected_text': corrected_text,
                    'errors': errors_response,
                    'themes': themes_response,
                    'topics': topics_data
                })
                
            except Exception as ai_error:
                logger.error(f"Error calling Mistral AI: {ai_error}")
                # Fallback: создаем запись без исправлений
                text_check = TextCheck.objects.create(
                    user=request.user,
                    original_text=text,
                    corrected_text=text
                )
                
                return JsonResponse({
                    'status': 'error',
                    'message': f'Ошибка при проверке текста: {str(ai_error)}',
                    'original_text': text,
                    'corrected_text': text,
                    'errors': [],
                    'themes': [],
                    'topics': []
                }, status=500)
            
        except json.JSONDecodeError:
            return JsonResponse({
                'status': 'error',
                'message': 'Неверный формат запроса'
            }, status=400)
        except Exception as e:
            logger.error(f"Error in check_text: {e}")
            return JsonResponse({
                'status': 'error',
                'message': str(e)
            }, status=500)
    
    return JsonResponse({
        'status': 'error',
        'message': 'Only POST method is allowed'
    }, status=405)

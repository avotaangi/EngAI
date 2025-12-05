from django.shortcuts import render
from django.http import HttpResponseNotFound, HttpResponseServerError, JsonResponse
from django.contrib.auth.decorators import login_required
from django.views.decorators.http import require_POST, require_http_methods
from django.views.decorators.csrf import csrf_exempt
from users.models import LanguageLevelTest, User
import json
import os
import time
import logging
from mistralai.client import MistralClient
from mistralai.models.chat_completion import ChatMessage
from django.utils import timezone

logger = logging.getLogger(__name__)


def custom_404_view(request, exception):
    """
    Кастомная страница 404 ошибки
    """
    return render(request, '404.html', status=404)


def custom_500_view(request):
    """
    Кастомная страница 500 ошибки
    """
    return render(request, '500.html', status=500)


def page_not_found_view(request):
    """
    Альтернативное представление для 404 ошибки
    Может использоваться для тестирования в режиме DEBUG=True
    """
    return render(request, '404.html')


@login_required
def dashboard_view(request):
    """
    Главная страница dashboard с обзором обучения
    """
    # Получаем последний тест уровня языка пользователя
    last_test = LanguageLevelTest.objects.filter(user=request.user).order_by('-created_at').first()
    
    context = {
        'user': request.user,
        'page_title': 'Главная - EngAI',
        'last_test': last_test,
        'has_completed_test': last_test and last_test.is_completed() if last_test else False
    }
    return render(request, 'dashboard.html', context)


@login_required
def level_test_view(request):
    """
    Страница теста уровня языка
    """
    # Получаем последний тест уровня языка пользователя
    last_test = LanguageLevelTest.objects.filter(user=request.user).order_by('-created_at').first()
    
    context = {
        'user': request.user,
        'page_title': 'Проверка уровня языка - EngAI',
        'last_test': last_test,
        'has_completed_test': last_test and last_test.is_completed() if last_test else False
    }
    return render(request, 'level_test.html', context)


@login_required
@require_POST
def start_level_test(request):
    """Начать новый тест уровня языка - генерирует вопросы через AI"""
    try:
        api_key = os.getenv('MISTRAL_API_KEY')
        if not api_key:
            return JsonResponse({'error': 'AI не настроен'}, status=500)
        
        # Создаем новый тест
        test = LanguageLevelTest.objects.create(user=request.user)
        
        # Генерируем вопросы через AI
        prompt = (
            "You are an English language assessment expert. Create a comprehensive level test with 20 questions "
            "that will help determine the user's English level (A1, A2, B1, B2, C1, C2).\n\n"
            "You MUST respond with ONLY valid JSON in this exact format:\n"
            "{\n"
            "  \"questions\": [\n"
            "    {\n"
            "      \"id\": 1,\n"
            "      \"type\": \"grammar|vocabulary|writing\",\n"
            "      \"question\": \"Question text\",\n"
            "      \"options\": [\"Option A\", \"Option B\", \"Option C\", \"Option D\"],\n"
            "      \"correct_answer\": 0,\n"
            "      \"explanation\": \"Why this answer is correct\",\n"
            "      \"level\": \"A1|A2|B1|B2|C1|C2\"\n"
            "    }\n"
            "  ]\n"
            "}\n\n"
            "CRITICAL RULES:\n"
            "1. Create exactly 20 questions\n"
            "2. Question types distribution:\n"
            "   - Grammar: 10 questions (verb tenses, articles, prepositions, conditionals, passive voice, etc.)\n"
            "   - Vocabulary: 6 questions (word choice, synonyms, collocations, phrasal verbs, idioms)\n"
            "   - Writing: 4 questions (sentence structure, word order, style, coherence)\n"
            "3. Level distribution:\n"
            "   - A1-A2: 5 questions (basic grammar, simple vocabulary)\n"
            "   - B1-B2: 10 questions (intermediate grammar, common vocabulary, sentence structure)\n"
            "   - C1-C2: 5 questions (advanced grammar, complex vocabulary, sophisticated writing)\n"
            "4. Each question must have exactly 4 options\n"
            "5. correct_answer is the index (0-3) of the correct option\n"
            "6. Provide clear explanations for each answer\n"
            "7. NEVER add any text before or after the JSON\n"
            "8. Make questions progressively more difficult\n"
            "9. For grammar questions: focus on tenses, articles, prepositions, modal verbs, conditionals\n"
            "10. For vocabulary questions: test word meaning, collocations, phrasal verbs, idioms\n"
            "11. For writing questions: test sentence structure, word order, style, coherence (NO punctuation marks in questions)\n"
            "12. Questions should be clear and unambiguous\n"
        )
        
        start_time = time.time()
        client = MistralClient(api_key=api_key)
        chat_messages = [
            ChatMessage(role="system", content=prompt),
            ChatMessage(role="user", content="Generate a comprehensive English level test with 20 questions focusing on grammar, vocabulary, and writing.")
        ]
        
        resp = client.chat(
            model="mistral-small",
            messages=chat_messages,
            temperature=0.7
        )
        
        raw_response = resp.choices[0].message.content if getattr(resp, 'choices', None) else None
        
        if not raw_response:
            test.delete()
            return JsonResponse({'error': 'Ошибка генерации вопросов'}, status=500)
        
        # Очищаем от markdown блоков
        clean_response = raw_response.strip()
        if clean_response.startswith('```'):
            lines = clean_response.split('\n')
            if lines[0].startswith('```'):
                lines = lines[1:]
            if lines and lines[-1].strip() == '```':
                lines = lines[:-1]
            clean_response = '\n'.join(lines).strip()
        
        # Парсим JSON
        try:
            parsed = json.loads(clean_response)
            questions = parsed.get('questions', [])
            
            if len(questions) != 20:
                test.delete()
                return JsonResponse({'error': f'Неверное количество вопросов: получено {len(questions)}, ожидается 20'}, status=500)
            
            # Сохраняем вопросы в тест
            test.questions = questions
            test.save()
            
            # Возвращаем только вопросы без правильных ответов
            questions_for_user = []
            for q in questions:
                questions_for_user.append({
                    'id': q.get('id'),
                    'type': q.get('type'),
                    'question': q.get('question'),
                    'options': q.get('options'),
                    'level': q.get('level')
                })
            
            return JsonResponse({
                'test_id': test.id,
                'questions': questions_for_user
            })
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse AI response: {e}. Raw: {raw_response[:500]}")
            test.delete()
            return JsonResponse({'error': 'Ошибка парсинга ответа AI'}, status=500)
            
    except Exception as e:
        logger.error(f"Error in start_level_test: {e}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
@require_POST
def submit_level_test(request):
    """Отправить ответы на тест и получить результат с анализом AI"""
    try:
        data = json.loads(request.body)
        test_id = data.get('test_id')
        answers = data.get('answers', [])  # Список индексов выбранных ответов
        
        if not test_id:
            return JsonResponse({'error': 'ID теста не указан'}, status=400)
        
        test = LanguageLevelTest.objects.filter(id=test_id, user=request.user).first()
        if not test:
            return JsonResponse({'error': 'Тест не найден'}, status=404)
        
        if test.is_completed():
            return JsonResponse({'error': 'Тест уже завершен'}, status=400)
        
        # Сохраняем ответы
        test.answers = answers
        test.save()
        
        # Проверяем ответы и вычисляем балл
        questions = test.questions
        correct_count = 0
        total_questions = len(questions)
        
        for i, question in enumerate(questions):
            if i < len(answers):
                user_answer = answers[i]
                correct_answer = question.get('correct_answer', -1)
                if user_answer == correct_answer:
                    correct_count += 1
        
        score = int((correct_count / total_questions) * 100) if total_questions > 0 else 0
        test.score = score
        test.max_score = 100
        
        # Анализируем результаты через AI для определения уровня и рекомендаций
        api_key = os.getenv('MISTRAL_API_KEY')
        if api_key:
            analysis_prompt = (
                "You are an English language assessment expert. Analyze the test results and determine the user's level.\n\n"
                "Test Results:\n"
                f"Score: {score}/100\n"
                f"Correct answers: {correct_count}/{total_questions}\n\n"
                "Questions and answers:\n"
            )
            
            for i, question in enumerate(questions):
                user_ans = answers[i] if i < len(answers) else -1
                correct_ans = question.get('correct_answer', -1)
                is_correct = user_ans == correct_ans
                analysis_prompt += f"\nQ{i+1} ({question.get('level', 'Unknown')}): {question.get('question', '')}\n"
                analysis_prompt += f"User answered: {user_ans} {'✓' if is_correct else '✗'}\n"
            
            analysis_prompt += (
                "\nYou MUST respond with ONLY valid JSON in this exact format:\n"
                "{\n"
                "  \"detected_level\": \"A1|A2|B1|B2|C1|C2\",\n"
                "  \"recommended_topics\": [\n"
                "    {\n"
                "      \"name\": \"Topic name in Russian\",\n"
                "      \"description\": \"Why this topic is important\",\n"
                "      \"priority\": \"high|medium|low\"\n"
                "    }\n"
                "  ],\n"
                "  \"analysis\": \"Detailed analysis of strengths and weaknesses in Russian\"\n"
                "}\n\n"
                "CRITICAL RULES:\n"
                "1. Determine level based on score and which level questions were answered correctly\n"
                "2. If user answered mostly A1-A2 questions correctly but failed B1+, suggest A2\n"
                "3. If user answered B1-B2 questions correctly, suggest B1 or B2\n"
                "4. If user answered C1-C2 questions correctly, suggest C1 or C2\n"
                "5. Provide 5-8 recommended topics based on mistakes\n"
                "6. Topics should be in Russian\n"
                "7. NEVER add any text before or after the JSON\n"
            )
            
            try:
                client = MistralClient(api_key=api_key)
                chat_messages = [
                    ChatMessage(role="system", content=analysis_prompt),
                    ChatMessage(role="user", content="Analyze the test results and provide recommendations.")
                ]
                
                resp = client.chat(
                    model="mistral-small",
                    messages=chat_messages,
                    temperature=0.3
                )
                
                raw_analysis = resp.choices[0].message.content if getattr(resp, 'choices', None) else None
                
                if raw_analysis:
                    clean_analysis = raw_analysis.strip()
                    if clean_analysis.startswith('```'):
                        lines = clean_analysis.split('\n')
                        if lines[0].startswith('```'):
                            lines = lines[1:]
                        if lines and lines[-1].strip() == '```':
                            lines = lines[:-1]
                        clean_analysis = '\n'.join(lines).strip()
                    
                    try:
                        analysis_data = json.loads(clean_analysis)
                        test.detected_level = analysis_data.get('detected_level', 'A1')
                        test.recommended_topics = analysis_data.get('recommended_topics', [])
                        test.ai_analysis = analysis_data
                        
                        # Обновляем уровень пользователя
                        if test.detected_level:
                            request.user.current_language_level = test.detected_level
                            request.user.save(update_fields=['current_language_level'])
                    except json.JSONDecodeError:
                        logger.warning(f"Failed to parse AI analysis: {raw_analysis[:200]}")
            except Exception as e:
                logger.error(f"Error in AI analysis: {e}")
        
        # Завершаем тест
        test.completed_at = timezone.now()
        test.save()
        
        return JsonResponse({
            'test_id': test.id,
            'score': score,
            'max_score': 100,
            'correct_count': correct_count,
            'total_questions': total_questions,
            'detected_level': test.detected_level,
            'recommended_topics': test.recommended_topics,
            'analysis': test.ai_analysis.get('analysis', '') if test.ai_analysis else ''
        })
        
    except json.JSONDecodeError:
        return JsonResponse({'error': 'Неверный формат запроса'}, status=400)
    except Exception as e:
        logger.error(f"Error in submit_level_test: {e}")
        return JsonResponse({'error': str(e)}, status=500)

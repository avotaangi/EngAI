from django.urls import path
from . import views

app_name = 'cards'

urlpatterns = [
    path('', views.cards_view, name='cards'),
    path('folder/<int:folder_id>/', views.folder_view, name='folder'),
    path('module/<int:module_id>/', views.module_view, name='module'),
    path('module/<int:module_id>/learn/', views.learn_module, name='learn_module'),
    path('module/<int:module_id>/test/', views.module_test, name='module_test'),
    path('module/<int:module_id>/match/', views.module_match, name='module_match'),
    path('module/<int:module_id>/bubble-game/', views.bubble_game, name='bubble_game'),
    path('module/<int:module_id>/bubble-game/record/', views.get_bubble_game_record, name='get_bubble_game_record'),
    path('module/<int:module_id>/bubble-game/save-record/', views.save_bubble_game_record, name='save_bubble_game_record'),
    path('update-progress/', views.update_learning_progress, name='update_learning_progress'),
    path('import-quizlet/', views.import_quizlet, name='import_quizlet'),
    path('module/<int:module_id>/balloon-game/', views.balloon_game, name='balloon_game'),
    path('module/<int:module_id>/balloon-game/record/', views.get_balloon_game_record, name='get_balloon_game_record'),
    path('module/<int:module_id>/balloon-game/save-record/', views.save_balloon_game_record,
         name='save_balloon_game_record'),
    path('module/<int:module_id>/ai-training/', views.ai_training, name='ai_training'),
    path('sidebar-chat/', views.sidebar_chat, name='sidebar_chat'),
    path('ai-speak/', views.ai_speak, name='ai_speak'),
    path('media-center/', views.media_center, name='media_center'),
    path('media/<str:media_type>/<int:media_id>/', views.media_detail, name='media_detail'),
    path('media/<str:media_type>/<int:media_id>/generate-lexicon/', views.generate_media_lexicon, name='generate_media_lexicon'),

    # Маршрут для экспорта модуля в Word

    
    # API endpoints для папок
    path('api/folders/', views.get_folders, name='get_folders'),
    path('api/create-folder/', views.create_folder, name='create_folder'),
    path('api/folder/<int:folder_id>/', views.get_folder, name='get_folder'),
    path('api/update-folder/<int:folder_id>/', views.update_folder, name='update_folder'),
    path('api/delete-folder/<int:folder_id>/', views.delete_folder, name='delete_folder'),
    
    # API endpoints для модулей
    path('api/modules/', views.get_modules, name='get_modules'),
    path('api/create-module/', views.create_module, name='create_module'),
    path('api/modules/<int:module_id>/', views.get_module, name='get_module'),
    path('api/modules/<int:module_id>/update/', views.update_module, name='update_module'),
    path('api/modules/<int:module_id>/delete/', views.delete_module, name='delete_module'),
    path('api/modules/<int:module_id>/cards/', views.get_module_cards, name='get_module_cards'),
    path('api/modules/<int:module_id>/cards/create/', views.create_card, name='create_card'),
    path('api/saved-modules/', views.get_saved_modules, name='get_saved_modules'),
    path('api/save-module/<int:module_id>/', views.save_module, name='save_module'),
    
    # API endpoints для карточек
    path('api/cards/<int:card_id>/update/', views.update_card, name='update_card'),
    path('api/cards/<int:card_id>/delete/', views.delete_card, name='delete_card'),
    path('api/chat-ai/', views.api_chat_ai, name='api_chat_ai'),
    path('api/translate/', views.api_translate_message, name='api_translate_message'),
    path('api/clear-chat/', views.api_clear_ai_chat, name='api_clear_ai_chat'),
    path('api/tts/', views.api_tts, name='api_tts'),
    path('api/asr/', views.api_asr, name='api_asr'),
    path('api/conversation-analytics/', views.api_conversation_analytics, name='api_conversation_analytics'),
    path('api/media-feed/', views.media_feed, name='media_feed'),
    
    # API endpoint для поиска
    path('api/search/', views.search_content, name='search_content'),
] 
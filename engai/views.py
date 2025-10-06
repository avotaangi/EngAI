from django.shortcuts import render
from django.http import HttpResponseNotFound, HttpResponseServerError


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
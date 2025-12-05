from django.db import models
from django.conf import settings

class TextCheck(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE)
    original_text = models.TextField()
    corrected_text = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-created_at']

class Error(models.Model):
    text_check = models.ForeignKey(TextCheck, on_delete=models.CASCADE, related_name='errors')
    error_text = models.CharField(max_length=255)
    correction = models.CharField(max_length=255)
    error_type = models.CharField(max_length=100)
    position = models.IntegerField()  # Позиция ошибки в тексте

class Theme(models.Model):
    text_check = models.ForeignKey(TextCheck, on_delete=models.CASCADE, related_name='themes', null=True, blank=True)
    name = models.CharField(max_length=100)
    description = models.TextField()
    errors = models.ManyToManyField(Error, related_name='themes', blank=True)

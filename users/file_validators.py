import os
import magic
from django.conf import settings
from django.core.exceptions import ValidationError
from django.utils.translation import gettext as _


class FileValidator:
    """Валидатор файлов для безопасной загрузки"""
    
    # MIME-типы для проверки реального содержимого файлов
    ALLOWED_MIME_TYPES = {
        'images': [
            'image/jpeg', 'image/png', 'image/gif', 
            'image/webp', 'image/bmp', 'image/tiff'
        ],
        'documents': [
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'text/plain'
        ],
        'archives': [
            'application/zip',
            'application/x-rar-compressed',
            'application/x-rar'
        ]
    }
    
    # Опасные расширения файлов
    DANGEROUS_EXTENSIONS = [
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif',
        '.vbs', '.js', '.jar', '.py', '.php', '.asp',
        '.jsp', '.sh', '.ps1'
    ]
    
    @classmethod
    def validate_file(cls, uploaded_file):
        """Основная функция валидации файла"""
        errors = []
        
        # Проверка расширения файла
        file_ext = cls._get_file_extension(uploaded_file.name)
        if not cls._is_extension_allowed(file_ext):
            errors.append(_('Недопустимый тип файла: {}').format(file_ext))
        
        # Проверка на опасные расширения
        if file_ext.lower() in cls.DANGEROUS_EXTENSIONS:
            errors.append(_('Загрузка исполняемых файлов запрещена'))
        
        # Проверка размера файла
        file_type = cls._get_file_type(file_ext)
        if not cls._is_file_size_valid(uploaded_file.size, file_type):
            max_size = cls._get_max_size_for_type(file_type)
            errors.append(_('Размер файла превышает допустимый лимит: {} MB').format(max_size // (1024 * 1024)))
        
        # Проверка MIME-типа (если возможно)
        try:
            mime_type = cls._get_mime_type(uploaded_file)
            if mime_type and not cls._is_mime_type_allowed(mime_type, file_type):
                errors.append(_('Содержимое файла не соответствует его расширению'))
        except Exception:
            # Если не удается определить MIME-тип, продолжаем без этой проверки
            pass
        
        # Проверка имени файла на безопасность
        if not cls._is_filename_safe(uploaded_file.name):
            errors.append(_('Имя файла содержит недопустимые символы'))
        
        if errors:
            raise ValidationError(errors)
        
        return True
    
    @classmethod
    def _get_file_extension(cls, filename):
        """Получить расширение файла"""
        return os.path.splitext(filename.lower())[1]
    
    @classmethod
    def _is_extension_allowed(cls, file_ext):
        """Проверить, разрешено ли расширение файла"""
        allowed_extensions = getattr(settings, 'ALLOWED_FILE_EXTENSIONS', {})
        all_allowed = []
        for extensions in allowed_extensions.values():
            all_allowed.extend(extensions)
        return file_ext.lower() in all_allowed
    
    @classmethod
    def _get_file_type(cls, file_ext):
        """Определить тип файла по расширению"""
        allowed_extensions = getattr(settings, 'ALLOWED_FILE_EXTENSIONS', {})
        
        for file_type, extensions in allowed_extensions.items():
            if file_ext.lower() in extensions:
                return file_type
        return 'unknown'
    
    @classmethod
    def _is_file_size_valid(cls, file_size, file_type):
        """Проверить размер файла"""
        max_sizes = getattr(settings, 'MAX_FILE_SIZES', {})
        max_size = max_sizes.get(file_type, 10 * 1024 * 1024)  # По умолчанию 10MB
        return file_size <= max_size
    
    @classmethod
    def _get_max_size_for_type(cls, file_type):
        """Получить максимальный размер для типа файла"""
        max_sizes = getattr(settings, 'MAX_FILE_SIZES', {})
        return max_sizes.get(file_type, 10 * 1024 * 1024)  # По умолчанию 10MB
    
    @classmethod
    def _get_mime_type(cls, uploaded_file):
        """Определить MIME-тип файла по его содержимому"""
        try:
            # Попытка использовать python-magic для определения MIME-типа
            file_start = uploaded_file.read(1024)
            uploaded_file.seek(0)  # Возвращаем указатель в начало файла
            
            # Используем magic для определения типа файла
            mime = magic.Magic(mime=True)
            return mime.from_buffer(file_start)
        except Exception:
            return None
    
    @classmethod
    def _is_mime_type_allowed(cls, mime_type, file_type):
        """Проверить, соответствует ли MIME-тип типу файла"""
        allowed_mimes = cls.ALLOWED_MIME_TYPES.get(file_type, [])
        return mime_type in allowed_mimes
    
    @classmethod
    def _is_filename_safe(cls, filename):
        """Проверить безопасность имени файла"""
        # Проверяем на наличие опасных символов и путей
        dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        filename_lower = filename.lower()
        
        # Проверка на опасные символы
        for char in dangerous_chars:
            if char in filename:
                return False
        
        # Проверка на слишком длинное имя файла
        if len(filename) > 255:
            return False
        
        # Проверка на пустое имя файла
        if not filename.strip():
            return False
        
        return True
    
    @classmethod
    def sanitize_filename(cls, filename):
        """Очистка имени файла от опасных символов"""
        import re
        import uuid
        
        # Получаем расширение файла
        name, ext = os.path.splitext(filename)
        
        # Удаляем опасные символы из имени
        safe_name = re.sub(r'[^\w\-_\.]', '_', name)
        
        # Ограничиваем длину имени файла
        if len(safe_name) > 100:
            safe_name = safe_name[:100]
        
        # Если имя файла пустое после очистки, генерируем новое
        if not safe_name:
            safe_name = str(uuid.uuid4())[:8]
        
        return safe_name + ext


def validate_chat_file(uploaded_file):
    """Специальная валидация для файлов чата"""
    return FileValidator.validate_file(uploaded_file)


def get_file_type_from_extension(filename):
    """Определить тип файла по расширению для отображения иконок"""
    ext = os.path.splitext(filename.lower())[1]
    
    image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp']
    document_extensions = ['.pdf', '.doc', '.docx', '.txt']
    archive_extensions = ['.zip', '.rar']
    
    if ext in image_extensions:
        return 'image'
    elif ext in document_extensions:
        return 'document'
    elif ext in archive_extensions:
        return 'archive'
    else:
        return 'file'


def format_file_size(size_bytes):
    """Форматирование размера файла для отображения"""
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    import math
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 2)
    return f"{s} {size_names[i]}"
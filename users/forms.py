from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.contrib.auth import get_user_model
from .models import User

User = get_user_model()


class LoginForm(AuthenticationForm):
    username = forms.EmailField(
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email',
            'id': 'id_email',
            'autofocus': 'autofocus',
            'required': 'required'
        })
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Пароль',
            'id': 'id_password',
            'required': 'required',
            'autocomplete': 'current-password'
        })
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['username'].label = 'Email'






class RegistrationForm(UserCreationForm):
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email',
            'required': 'required'
        })
    )
    password1 = forms.CharField(
        label='Пароль',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Пароль',
            'required': 'required'
        })
    )
    password2 = forms.CharField(
        label='Подтверждение пароля',
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Подтвердите пароль',
            'required': 'required'
        })
    )
    first_name = forms.CharField(
        label='Имя',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Имя',
            'required': 'required'
        })
    )
    last_name = forms.CharField(
        label='Фамилия',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Фамилия',
            'required': 'required'
        })
    )
    phone_number = forms.CharField(
        label='Телефон',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Телефон',
            'required': 'required'
        })
    )
    current_language_level = forms.ChoiceField(
        label='Текущий уровень языка',
        choices=[
            ('', 'Выберите уровень'),
            ('A1', 'А1 — Начальный'),
            ('A2', 'А2 — Элементарный'),
            ('B1', 'B1 — Средний'),
            ('B2', 'B2 — Выше среднего'),
            ('C1', 'C1 — Продвинутый'),
            ('C2', 'C2 — Свободный'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-control',
            'required': 'required',
            'onchange': 'updateDesiredLevels(this.value)'
        })
    )
    desired_language_level = forms.ChoiceField(
        label='Желаемый уровень',
        choices=[
            ('', 'Выберите уровень'),
            ('A2', 'А2 — Элементарный'),
            ('B1', 'B1 — Средний'),
            ('B2', 'B2 — Выше среднего'),
            ('C1', 'C1 — Продвинутый'),
            ('C2', 'C2 — Свободный'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-control',
            'required': 'required'
        })
    )
    city = forms.CharField(
        label='Город',
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Город проживания',
            'required': 'required'
        })
    )

    class Meta:
        model = User
        fields = ('email', 'password1', 'password2', 'first_name', 'last_name', 
                 'phone_number', 'current_language_level', 'desired_language_level', 'city')

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('Пользователь с таким email уже существует')
        return email

    def clean_password2(self):
        password1 = self.cleaned_data.get('password1')
        password2 = self.cleaned_data.get('password2')
        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Пароли не совпадают')
        return password2

    def clean(self):
        cleaned_data = super().clean()
        current_level = cleaned_data.get('current_language_level')
        desired_level = cleaned_data.get('desired_language_level')

        if current_level and desired_level:
            levels = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']
            current_index = levels.index(current_level)
            desired_index = levels.index(desired_level)

            if desired_index <= current_index:
                raise forms.ValidationError('Желаемый уровень должен быть выше текущего уровня')

        return cleaned_data


class ProfileEditForm(forms.ModelForm):
    first_name = forms.CharField(
        label='Имя',
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Имя'
        })
    )
    last_name = forms.CharField(
        label='Фамилия', 
        max_length=30,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Фамилия'
        })
    )
    email = forms.EmailField(
        label='Email',
        widget=forms.EmailInput(attrs={
            'class': 'form-control',
            'placeholder': 'Email',
            'readonly': True
        })
    )
    phone_number = forms.CharField(
        label='Номер телефона',
        max_length=20,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': '+7 (999) 123-45-67'
        })
    )
    city = forms.CharField(
        label='Город',
        max_length=100,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control',
            'placeholder': 'Город проживания'
        })
    )
    birth_date = forms.DateField(
        label='Дата рождения',
        required=False,
        widget=forms.DateInput(attrs={
            'class': 'form-control',
            'type': 'date'
        })
    )
    current_language_level = forms.ChoiceField(
        label='Текущий уровень языка',
        choices=[
            ('A1', 'А1 — Начальный'),
            ('A2', 'А2 — Элементарный'),
            ('B1', 'B1 — Средний'),
            ('B2', 'B2 — Выше среднего'),
            ('C1', 'C1 — Продвинутый'),
            ('C2', 'C2 — Свободный'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )
    desired_language_level = forms.ChoiceField(
        label='Желаемый уровень языка',
        choices=[
            ('A2', 'А2 — Элементарный'),
            ('B1', 'B1 — Средний'),
            ('B2', 'B2 — Выше среднего'),
            ('C1', 'C1 — Продвинутый'),
            ('C2', 'C2 — Свободный'),
        ],
        widget=forms.Select(attrs={
            'class': 'form-control'
        })
    )

    class Meta:
        model = User
        fields = ['first_name', 'last_name', 'email', 'phone_number', 'city', 
                 'birth_date', 'current_language_level', 'desired_language_level']

    def clean(self):
        cleaned_data = super().clean()
        current_level = cleaned_data.get('current_language_level')
        desired_level = cleaned_data.get('desired_language_level')

        if current_level and desired_level:
            levels = ['A1', 'A2', 'B1', 'B2', 'C1', 'C2']
            current_index = levels.index(current_level)
            desired_index = levels.index(desired_level)

            if desired_index <= current_index:
                raise forms.ValidationError('Желаемый уровень должен быть выше текущего уровня')

        return cleaned_data


class PasswordChangeForm(forms.Form):
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Новый пароль',
            'required': 'required'
        })
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'class': 'form-control',
            'placeholder': 'Повторите пароль',
            'required': 'required'
        })
    )

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get('password1')
        password2 = cleaned_data.get('password2')

        if password1 and password2 and password1 != password2:
            raise forms.ValidationError('Пароли не совпадают')

        return cleaned_data

    def save(self, user, commit=True):
        user.set_password(self.cleaned_data['password1'])
        if commit:
            user.save()
        return user

from django.shortcuts import render, redirect
from django.views.generic import View
from django.contrib import messages
from django.contrib.auth.models import User
from django.core.mail import EmailMessage, EmailMultiAlternatives
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text, DjangoUnicodeDecodeError
from django.conf import settings
from django.contrib.auth import authenticate, login, logout
from validate_email import validate_email

from .utils import generate_token

# Create your views here.


class RegistrationView(View):
    def get(self, request):
        return render(request, 'auth/register.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        email = request.POST.get('email')
        username = request.POST.get('username')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        name = request.POST.get('name')

        # validate password
        if len(password) < 6:
            messages.add_message(request, messages.ERROR,
                                 'Passwords should be 6 character long')
            context['has_error'] = True

        if password != password2:
            messages.add_message(request, messages.ERROR,
                                 'Passwords dont match')
            context['has_error'] = True

        # validate email
        if not validate_email(email):
            messages.add_message(request, messages.ERROR,
                                 'Please provide a valid email')
            context['has_error'] = True

        if User.objects.filter(email=email).exists():
            messages.add_message(request, messages.ERROR,
                                 'Please email is already taken')
            context['has_error'] = True

        if User.objects.filter(username=username).exists():
            messages.add_message(request, messages.ERROR,
                                 'Please username is already taken')
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'auth/register.html', context=context)

        user = User.objects.create_user(username=username, email=email)
        user.set_password(password)
        user.first_name = name
        user.is_active = False
        user.save()

        # send email
        current_site = get_current_site(request)
        email_subject = 'Active your account'
        messsage = render_to_string('email/active.html', {
            'user': user,
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'token': generate_token.make_token(user)
        })

        # send_mail('Active your account', 'Here is the message.',
        # 'from@example.com', [email], fail_silently=False)

        email_message = EmailMessage(
            email_subject,
            messsage,
            settings.EMAIL_HOST_USER,
            [email],
            ['jt@amediaagency.com'],
        )
        email_message.content_subtype = "html"
        email_message.send()

        messages.add_message(request, messages.SUCCESS,
                             'Your account is creating successfully')

        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'auth/login.html')

    def post(self, request):
        context = {
            'data': request.POST,
            'has_error': False
        }
        username = request.POST.get('username')
        password = request.POST.get('password')

        if username == '':
            messages.add_message(request, messages.ERROR,
                                 "Username can't be blank")
            context['has_error'] = True

        if password == '':
            messages.add_message(request, messages.ERROR,
                                 "Password can't be blank")
            context['has_error'] = True

        if context['has_error']:
            return render(request, 'auth/login.html', status=401, context=context)

        user = authenticate(request, username=username, password=password)

        if not user and not context['has_error']:
            messages.add_message(request, messages.ERROR,
                                 "Invalid login")
            context['has_error'] = True
            return render(request, 'auth/login.html', context=context)

        login(request, user)
        return redirect('home')


class ActivateAccountView(View):
    def get(self, request, uidb64, token):
        try:
            uid = force_text(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
            user.is_active = True
        except Exception as identifier:
            user = None

        if user is not None and generate_token.check_token(user, token):
            user.is_active = True
            user.save()
            messages.add_message(request, messages.SUCCESS,
                                 'Your account is actived successfully')

            return redirect('login')

        return render(request, 'auth/activate_failed.html', status=401)


class HomeView(View):
    def get(self, request):
        return render(request, 'home/index.html')


class LogoutView(View):
    def post(self, request):
        logout(request)
        messages.add_message(request, messages.SUCCESS,
                             'Logout successfully')
        return redirect('login')

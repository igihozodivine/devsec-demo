from django.contrib import messages
from django.contrib.auth import REDIRECT_FIELD_NAME, login, logout
from django.contrib.auth.mixins import LoginRequiredMixin, UserPassesTestMixin
from django.contrib.auth.models import User
from django.contrib.auth.views import (
    LoginView,
    PasswordChangeDoneView,
    PasswordChangeView,
    PasswordResetCompleteView,
    PasswordResetConfirmView,
    PasswordResetDoneView,
    PasswordResetView,
)
from django.http import JsonResponse
from django.http import Http404
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.shortcuts import redirect
from django.urls import reverse_lazy
from django.views.generic import FormView, TemplateView

from .redirects import DEFAULT_POST_AUTH_REDIRECT, get_safe_redirect, get_safe_redirect_for_template
from .audit import hash_identifier, log_security_event
from .authz import user_is_privileged
from .forms import (
    AccountUpdateForm,
    LoginForm,
    RegistrationForm,
    StyledPasswordChangeForm,
    StyledPasswordResetForm,
    StyledSetPasswordForm,
)
from .throttling import clear_login_throttle, get_client_ip, get_login_throttle_state, register_failed_login


class HomeView(TemplateView):
    template_name = "igihozo/home.html"


class RegisterView(FormView):
    template_name = "igihozo/register.html"
    form_class = RegistrationForm
    success_url = DEFAULT_POST_AUTH_REDIRECT

    def dispatch(self, request, *args, **kwargs):
        if request.user.is_authenticated:
            return redirect("igihozo:account")
        return super().dispatch(request, *args, **kwargs)

    def form_valid(self, form):
        user = form.save()
        login(self.request, user)
        log_security_event("registration", request=self.request, actor=user, target_user=user)
        messages.success(self.request, "Your account has been created and you are now signed in.")
        return super().form_valid(form)

    def get_success_url(self):
        return get_safe_redirect(self.request, fallback_url=str(DEFAULT_POST_AUTH_REDIRECT))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["next_target"] = get_safe_redirect_for_template(self.request)
        return context


class UserLoginView(LoginView):
    template_name = "igihozo/login.html"
    authentication_form = LoginForm
    redirect_authenticated_user = True
    redirect_field_name = REDIRECT_FIELD_NAME

    def dispatch(self, request, *args, **kwargs):
        self.login_identifier = (request.POST.get("username") or "").strip()
        self.client_ip = get_client_ip(request)
        self.throttle_state = get_login_throttle_state(self.login_identifier, self.client_ip)
        return super().dispatch(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        if self.throttle_state["is_blocked"]:
            log_security_event(
                "login_failure",
                request=request,
                actor_username=self.login_identifier,
                outcome="blocked",
                details={"reason": "temporary_cooldown"},
            )
            form = self.get_form()
            form.add_error(
                None,
                (
                    "Too many failed sign-in attempts were detected. "
                    f"Please wait about {self.throttle_state['remaining_seconds']} seconds and try again."
                ),
            )
            response = self.form_invalid(form)
            response.status_code = 429
            return response
        return super().post(request, *args, **kwargs)

    def form_valid(self, form):
        clear_login_throttle(self.login_identifier or form.get_user().get_username(), self.client_ip)
        log_security_event("login_success", request=self.request, actor=form.get_user(), target_user=form.get_user())
        messages.success(self.request, "Welcome back. You have signed in successfully.")
        return super().form_valid(form)

    def form_invalid(self, form):
        if self.request.method == "POST" and not self.throttle_state["is_blocked"]:
            register_failed_login(self.login_identifier, self.client_ip)
            log_security_event(
                "login_failure",
                request=self.request,
                actor_username=self.login_identifier,
                outcome="failure",
                details={"reason": "invalid_credentials"},
            )
        return super().form_invalid(form)

    def get_success_url(self):
        return get_safe_redirect(self.request, fallback_url=str(DEFAULT_POST_AUTH_REDIRECT))

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["next_target"] = get_safe_redirect_for_template(self.request)
        return context


class UserLogoutView(TemplateView):
    template_name = "igihozo/logged_out.html"
    redirect_field_name = REDIRECT_FIELD_NAME

    def get(self, request, *args, **kwargs):
        return super().get(request, *args, **kwargs)

    def post(self, request, *args, **kwargs):
        safe_redirect = get_safe_redirect(request, fallback_url="")
        if request.user.is_authenticated:
            log_security_event("logout", request=request, actor=request.user, target_user=request.user)
        logout(request)
        if safe_redirect:
            return redirect(safe_redirect)
        return self.get(request, *args, **kwargs)


class AccountView(LoginRequiredMixin, FormView):
    template_name = "igihozo/account.html"
    form_class = AccountUpdateForm
    success_url = reverse_lazy("igihozo:account")
    login_url = reverse_lazy("igihozo:login")

    def dispatch(self, request, *args, **kwargs):
        if not request.user.is_authenticated:
            return self.handle_no_permission()
        return redirect("igihozo:profile_edit", username=request.user.username)


class OwnedProfileAccessMixin(LoginRequiredMixin):
    login_url = reverse_lazy("igihozo:login")
    allow_privileged_override = True

    def get_target_user(self):
        username = self.kwargs["username"]
        if user_is_privileged(self.request.user) and self.allow_privileged_override:
            return get_object_or_404(User.objects.select_related("profile"), username=username)

        if username != self.request.user.username:
            raise Http404("Profile not found.")

        return get_object_or_404(
            User.objects.select_related("profile").filter(pk=self.request.user.pk),
            username=username,
        )

    def get_role_labels(self, target_user):
        labels = []
        if target_user.is_superuser:
            labels.append("Administrator")
        elif target_user.is_staff:
            labels.append("Staff")

        group_names = set(target_user.groups.values_list("name", flat=True))
        if "instructors" in group_names:
            labels.append("Instructor")
        if "students" in group_names:
            labels.append("Student")
        return labels or ["Authenticated user"]


class ProfileDetailView(OwnedProfileAccessMixin, TemplateView):
    template_name = "igihozo/profile_detail.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        target_user = self.get_target_user()
        context["target_user"] = target_user
        context["role_labels"] = self.get_role_labels(target_user)
        context["is_owner"] = target_user.pk == self.request.user.pk
        context["is_privileged_user"] = user_is_privileged(self.request.user)
        return context


class ProfileEditView(OwnedProfileAccessMixin, FormView):
    template_name = "igihozo/account.html"
    form_class = AccountUpdateForm
    login_url = reverse_lazy("igihozo:login")

    @method_decorator(ensure_csrf_cookie)
    def dispatch(self, request, *args, **kwargs):
        self.target_user = self.get_target_user()
        return super().dispatch(request, *args, **kwargs)

    def get_success_url(self):
        return reverse_lazy("igihozo:profile_edit", kwargs={"username": self.target_user.username})

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = self.target_user.profile
        kwargs["user"] = self.target_user
        return kwargs

    def form_valid(self, form):
        form.save()
        log_security_event(
            "profile_update",
            request=self.request,
            actor=self.request.user,
            target_user=self.target_user,
            details={"via": "form"},
        )
        if self.target_user.pk == self.request.user.pk:
            messages.success(self.request, "Your profile has been updated.")
        else:
            messages.success(
                self.request,
                f"Profile for {self.target_user.username} has been updated successfully.",
            )
        return super().form_valid(form)

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["target_user"] = self.target_user
        context["is_privileged_user"] = user_is_privileged(self.request.user)
        context["role_labels"] = self.get_role_labels(self.target_user)
        context["is_owner"] = self.target_user.pk == self.request.user.pk
        return context


class ProfileAjaxUpdateView(OwnedProfileAccessMixin, FormView):
    form_class = AccountUpdateForm
    http_method_names = ["post"]
    login_url = reverse_lazy("igihozo:login")

    def dispatch(self, request, *args, **kwargs):
        self.target_user = self.get_target_user()
        return super().dispatch(request, *args, **kwargs)

    def get_form_kwargs(self):
        kwargs = super().get_form_kwargs()
        kwargs["instance"] = self.target_user.profile
        kwargs["user"] = self.target_user
        return kwargs

    def form_valid(self, form):
        form.save()
        log_security_event(
            "profile_update",
            request=self.request,
            actor=self.request.user,
            target_user=self.target_user,
            details={"via": "ajax"},
        )
        return JsonResponse(
            {
                "status": "ok",
                "message": "Profile changes saved securely.",
                "profile": {
                    "username": self.target_user.username,
                    "display_name": self.target_user.profile.display_name,
                    "email": self.target_user.email,
                    "bio": self.target_user.profile.bio,
                },
            }
        )

    def form_invalid(self, form):
        return JsonResponse({"status": "error", "errors": form.errors}, status=400)


class UserPasswordChangeView(LoginRequiredMixin, PasswordChangeView):
    template_name = "igihozo/password_change_form.html"
    form_class = StyledPasswordChangeForm
    success_url = reverse_lazy("igihozo:password_change_done")
    login_url = reverse_lazy("igihozo:login")

    def form_valid(self, form):
        log_security_event(
            "password_changed",
            request=self.request,
            actor=self.request.user,
            target_user=self.request.user,
        )
        messages.success(self.request, "Your password has been updated.")
        return super().form_valid(form)


class UserPasswordChangeDoneView(LoginRequiredMixin, PasswordChangeDoneView):
    template_name = "igihozo/password_change_done.html"
    login_url = reverse_lazy("igihozo:login")


class UserPasswordResetView(PasswordResetView):
    template_name = "igihozo/password_reset_form.html"
    email_template_name = "igihozo/emails/password_reset_email.txt"
    subject_template_name = "igihozo/emails/password_reset_subject.txt"
    success_url = reverse_lazy("igihozo:password_reset_done")
    form_class = StyledPasswordResetForm

    def form_valid(self, form):
        log_security_event(
            "password_reset_requested",
            request=self.request,
            actor_username=None,
            outcome="accepted",
            details={"submitted_email_hash": hash_identifier(form.cleaned_data["email"])},
        )
        return super().form_valid(form)


class UserPasswordResetDoneView(PasswordResetDoneView):
    template_name = "igihozo/password_reset_done.html"


class UserPasswordResetConfirmView(PasswordResetConfirmView):
    template_name = "igihozo/password_reset_confirm.html"
    success_url = reverse_lazy("igihozo:password_reset_complete")
    form_class = StyledSetPasswordForm

    def dispatch(self, request, *args, **kwargs):
        response = super().dispatch(request, *args, **kwargs)
        context_data = getattr(response, "context_data", {})
        if context_data.get("validlink") is False:
            log_security_event(
                "password_reset_invalid_link",
                request=request,
                outcome="rejected",
            )
        return response

    def form_valid(self, form):
        user = form.user
        log_security_event(
            "password_reset_completed",
            request=self.request,
            actor=user,
            target_user=user,
        )
        return super().form_valid(form)


class UserPasswordResetCompleteView(PasswordResetCompleteView):
    template_name = "igihozo/password_reset_complete.html"


class PrivilegedAccessMixin(LoginRequiredMixin, UserPassesTestMixin):
    login_url = reverse_lazy("igihozo:login")

    def test_func(self):
        return user_is_privileged(self.request.user)

    def handle_no_permission(self):
        if self.request.user.is_authenticated:
            return render(self.request, "403.html", status=403)
        return super().handle_no_permission()


class PrivilegedDashboardView(PrivilegedAccessMixin, TemplateView):
    template_name = "igihozo/privileged_dashboard.html"

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context["users"] = User.objects.select_related("profile").prefetch_related("groups").order_by(
            "username"
        )
        context["role_summary"] = {
            "anonymous_visitors": "Can browse public pages only and cannot access account features.",
            "authenticated_users": "Can manage their own account, profile, session, and password.",
            "privileged_users": "Can access the privileged dashboard and review registered users.",
        }
        return context


def permission_denied_view(request, exception, template_name="403.html"):
    return render(request, template_name, status=403)

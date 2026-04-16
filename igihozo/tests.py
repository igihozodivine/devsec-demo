import json

from django.contrib.auth.models import Group, Permission, User
from django.core.cache import cache
from django.core import mail
from django.test import Client, TestCase
from django.test import override_settings
from django.urls import reverse
from django.utils.encoding import force_bytes
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.tokens import default_token_generator


class AuthenticationFlowTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.user = User.objects.create_user(
            username="existinguser",
            email="existing@example.com",
            password=self.password,
        )

    def test_registration_creates_user_profile_and_logs_user_in(self):
        response = self.client.post(
            reverse("igihozo:register"),
            {
                "username": "newstudent",
                "first_name": "Igi",
                "last_name": "Hozo",
                "email": "newstudent@example.com",
                "display_name": "Igi Hozo",
                "bio": "Security-minded Django learner.",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
            follow=True,
        )

        self.assertRedirects(
            response,
            reverse("igihozo:profile_edit", kwargs={"username": "newstudent"}),
        )
        user = User.objects.get(username="newstudent")
        self.assertEqual(user.email, "newstudent@example.com")
        self.assertEqual(user.profile.display_name, "Igi Hozo")
        self.assertTrue(response.context["user"].is_authenticated)

    def test_registration_rejects_duplicate_email(self):
        response = self.client.post(
            reverse("igihozo:register"),
            {
                "username": "anotheruser",
                "email": "existing@example.com",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "An account with this email address already exists.")

    def test_login_and_logout_flow(self):
        login_response = self.client.post(
            reverse("igihozo:login"),
            {"username": "existinguser", "password": self.password},
            follow=True,
        )
        self.assertRedirects(
            login_response,
            reverse("igihozo:profile_edit", kwargs={"username": "existinguser"}),
        )
        self.assertTrue(login_response.context["user"].is_authenticated)

        logout_response = self.client.post(reverse("igihozo:logout"), follow=True)
        self.assertEqual(logout_response.status_code, 200)
        self.assertFalse(logout_response.context["user"].is_authenticated)
        self.assertContains(logout_response, "signed out")

    def test_account_page_requires_authentication(self):
        response = self.client.get(reverse("igihozo:account"))

        self.assertRedirects(
            response,
            f"{reverse('igihozo:login')}?next={reverse('igihozo:account')}",
        )

    def test_authenticated_user_can_update_profile(self):
        self.client.login(username="existinguser", password=self.password)

        response = self.client.post(
            reverse("igihozo:profile_edit", kwargs={"username": "existinguser"}),
            {
                "email": "updated@example.com",
                "first_name": "Updated",
                "last_name": "Student",
                "display_name": "Updated Student",
                "bio": "Updated bio",
            },
            follow=True,
        )

        self.assertRedirects(
            response,
            reverse("igihozo:profile_edit", kwargs={"username": "existinguser"}),
        )
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "updated@example.com")
        self.assertEqual(self.user.profile.display_name, "Updated Student")

    def test_account_route_redirects_to_owned_profile_edit_view(self):
        self.client.login(username="existinguser", password=self.password)

        response = self.client.get(reverse("igihozo:account"))

        self.assertRedirects(
            response,
            reverse("igihozo:profile_edit", kwargs={"username": "existinguser"}),
        )

    def test_password_change_updates_credentials(self):
        self.client.login(username="existinguser", password=self.password)

        response = self.client.post(
            reverse("igihozo:password_change"),
            {
                "old_password": self.password,
                "new_password1": "EvenStronger123!",
                "new_password2": "EvenStronger123!",
            },
            follow=True,
        )

        self.assertRedirects(response, reverse("igihozo:password_change_done"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("EvenStronger123!"))


class RoleBasedAccessControlTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.standard_user = User.objects.create_user(
            username="studentuser",
            email="student@example.com",
            password=self.password,
        )
        self.staff_user = User.objects.create_user(
            username="staffuser",
            email="staff@example.com",
            password=self.password,
            is_staff=True,
        )
        self.instructor_user = User.objects.create_user(
            username="instructoruser",
            email="instructor@example.com",
            password=self.password,
        )
        self.instructors_group = Group.objects.get(name="instructors")
        self.students_group = Group.objects.get(name="students")
        self.instructor_user.groups.add(self.instructors_group)

    def test_new_users_are_assigned_to_student_group(self):
        self.assertTrue(self.standard_user.groups.filter(name="students").exists())

    def test_anonymous_user_cannot_access_privileged_dashboard(self):
        response = self.client.get(reverse("igihozo:privileged_dashboard"))

        self.assertRedirects(
            response,
            f"{reverse('igihozo:login')}?next={reverse('igihozo:privileged_dashboard')}",
        )

    def test_authenticated_standard_user_gets_403_for_privileged_dashboard(self):
        self.client.login(username="studentuser", password=self.password)

        response = self.client.get(reverse("igihozo:privileged_dashboard"))

        self.assertEqual(response.status_code, 403)
        self.assertContains(response, "do not have permission", status_code=403)

    def test_instructor_group_user_can_access_privileged_dashboard(self):
        self.client.login(username="instructoruser", password=self.password)

        response = self.client.get(reverse("igihozo:privileged_dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Privileged dashboard")
        self.assertContains(response, "studentuser")

    def test_staff_user_can_access_privileged_dashboard(self):
        self.client.login(username="staffuser", password=self.password)

        response = self.client.get(reverse("igihozo:privileged_dashboard"))

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "Registered users")

    def test_instructor_group_receives_privileged_permission(self):
        permission = Permission.objects.get(codename="view_privileged_dashboard")

        self.assertTrue(self.instructors_group.permissions.filter(pk=permission.pk).exists())


class IdorProtectionTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.owner = User.objects.create_user(
            username="owneruser",
            email="owner@example.com",
            password=self.password,
        )
        self.other_user = User.objects.create_user(
            username="otheruser",
            email="other@example.com",
            password=self.password,
        )
        self.instructor = User.objects.create_user(
            username="instructoridor",
            email="instructoridor@example.com",
            password=self.password,
        )
        Group.objects.get(name="instructors").user_set.add(self.instructor)

    def test_user_can_view_own_identifier_based_profile(self):
        self.client.login(username="owneruser", password=self.password)

        response = self.client.get(
            reverse("igihozo:profile_detail", kwargs={"username": "owneruser"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "owneruser")

    def test_user_cannot_view_another_users_profile_by_changing_url(self):
        self.client.login(username="owneruser", password=self.password)

        response = self.client.get(
            reverse("igihozo:profile_detail", kwargs={"username": "otheruser"})
        )

        self.assertEqual(response.status_code, 404)

    def test_user_cannot_edit_another_users_profile_by_changing_url(self):
        self.client.login(username="owneruser", password=self.password)

        response = self.client.post(
            reverse("igihozo:profile_edit", kwargs={"username": "otheruser"}),
            {
                "email": "hijack@example.com",
                "first_name": "Hijack",
                "last_name": "Attempt",
                "display_name": "Hijack Attempt",
                "bio": "Trying to overwrite another profile.",
            },
        )

        self.assertEqual(response.status_code, 404)
        self.other_user.refresh_from_db()
        self.assertEqual(self.other_user.email, "other@example.com")

    def test_privileged_user_can_view_another_users_profile_for_authorized_workflow(self):
        self.client.login(username="instructoridor", password=self.password)

        response = self.client.get(
            reverse("igihozo:profile_detail", kwargs={"username": "otheruser"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "otheruser")

    def test_privileged_user_can_edit_another_users_profile_for_authorized_workflow(self):
        self.client.login(username="instructoridor", password=self.password)

        response = self.client.post(
            reverse("igihozo:profile_edit", kwargs={"username": "otheruser"}),
            {
                "email": "reviewed@example.com",
                "first_name": "Reviewed",
                "last_name": "Student",
                "display_name": "Reviewed Student",
                "bio": "Updated by privileged workflow.",
            },
            follow=True,
        )

        self.assertRedirects(
            response,
            reverse("igihozo:profile_edit", kwargs={"username": "otheruser"}),
        )
        self.other_user.refresh_from_db()
        self.assertEqual(self.other_user.email, "reviewed@example.com")


@override_settings(EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend")
class PasswordResetFlowTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.user = User.objects.create_user(
            username="resetuser",
            email="reset@example.com",
            password=self.password,
        )

    def test_password_reset_request_sends_email_for_existing_user(self):
        response = self.client.post(
            reverse("igihozo:password_reset"),
            {"email": "reset@example.com"},
            follow=True,
        )

        self.assertRedirects(response, reverse("igihozo:password_reset_done"))
        self.assertContains(response, "If an account exists")
        self.assertEqual(len(mail.outbox), 1)
        self.assertIn("/reset/", mail.outbox[0].body)

    def test_password_reset_request_does_not_leak_unknown_email(self):
        response = self.client.post(
            reverse("igihozo:password_reset"),
            {"email": "missing@example.com"},
            follow=True,
        )

        self.assertRedirects(response, reverse("igihozo:password_reset_done"))
        self.assertContains(response, "If an account exists")
        self.assertEqual(len(mail.outbox), 0)

    def test_password_reset_confirm_updates_password(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))
        token = default_token_generator.make_token(self.user)
        confirm_url = reverse(
            "igihozo:password_reset_confirm",
            kwargs={"uidb64": uid, "token": token},
        )

        initial_response = self.client.get(confirm_url, follow=True)
        post_url = initial_response.request["PATH_INFO"]

        response = self.client.post(
            post_url,
            {
                "new_password1": "BrandNewStrong123!",
                "new_password2": "BrandNewStrong123!",
            },
            follow=True,
        )

        self.assertRedirects(response, reverse("igihozo:password_reset_complete"))
        self.user.refresh_from_db()
        self.assertTrue(self.user.check_password("BrandNewStrong123!"))

    def test_password_reset_confirm_rejects_invalid_token(self):
        uid = urlsafe_base64_encode(force_bytes(self.user.pk))

        response = self.client.get(
            reverse("igihozo:password_reset_confirm", kwargs={"uidb64": uid, "token": "invalid-token"})
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "invalid or has already been used")


@override_settings(
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    LOGIN_THROTTLE_ACCOUNT_LIMIT=3,
    LOGIN_THROTTLE_IP_LIMIT=6,
    LOGIN_THROTTLE_WINDOW_SECONDS=120,
)
class LoginBruteForceProtectionTests(TestCase):
    def setUp(self):
        cache.clear()
        self.password = "ComplexPass123!"
        self.user = User.objects.create_user(
            username="throttleuser",
            email="throttle@example.com",
            password=self.password,
        )

    def test_normal_login_still_works_before_threshold(self):
        response = self.client.post(
            reverse("igihozo:login"),
            {"username": "throttleuser", "password": self.password},
            follow=True,
        )

        self.assertRedirects(
            response,
            reverse("igihozo:profile_edit", kwargs={"username": "throttleuser"}),
        )

    def test_repeated_failed_login_attempts_trigger_temporary_block(self):
        for _ in range(3):
            self.client.post(
                reverse("igihozo:login"),
                {"username": "throttleuser", "password": "WrongPassword123!"},
            )

        blocked_response = self.client.post(
            reverse("igihozo:login"),
            {"username": "throttleuser", "password": self.password},
        )

        self.assertEqual(blocked_response.status_code, 429)
        self.assertContains(blocked_response, "Too many failed sign-in attempts", status_code=429)
        self.assertFalse(blocked_response.wsgi_request.user.is_authenticated)

    def test_successful_login_clears_previous_failure_count(self):
        for _ in range(2):
            self.client.post(
                reverse("igihozo:login"),
                {"username": "throttleuser", "password": "WrongPassword123!"},
            )

        success_response = self.client.post(
            reverse("igihozo:login"),
            {"username": "throttleuser", "password": self.password},
            follow=True,
        )
        self.assertRedirects(
            success_response,
            reverse("igihozo:profile_edit", kwargs={"username": "throttleuser"}),
        )
        self.client.post(reverse("igihozo:logout"))

        follow_up_failure = self.client.post(
            reverse("igihozo:login"),
            {"username": "throttleuser", "password": "WrongPassword123!"},
        )

        self.assertEqual(follow_up_failure.status_code, 200)
        self.assertNotContains(follow_up_failure, "Too many failed sign-in attempts")


class CsrfProtectionTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.user = User.objects.create_user(
            username="csrfuser",
            email="csrf@example.com",
            password=self.password,
        )
        self.csrf_client = Client(enforce_csrf_checks=True)
        self.csrf_client.login(username="csrfuser", password=self.password)

    def test_ajax_profile_update_without_csrf_token_is_rejected(self):
        response = self.csrf_client.post(
            reverse("igihozo:profile_ajax_update", kwargs={"username": "csrfuser"}),
            {
                "email": "blocked@example.com",
                "first_name": "Blocked",
                "last_name": "Request",
                "display_name": "Blocked Request",
                "bio": "This should fail without CSRF.",
            },
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 403)

    def test_ajax_profile_update_with_csrf_token_succeeds(self):
        edit_page = self.csrf_client.get(
            reverse("igihozo:profile_edit", kwargs={"username": "csrfuser"})
        )
        csrf_token = edit_page.cookies["csrftoken"].value

        response = self.csrf_client.post(
            reverse("igihozo:profile_ajax_update", kwargs={"username": "csrfuser"}),
            {
                "email": "secured@example.com",
                "first_name": "Secure",
                "last_name": "Update",
                "display_name": "Secure Update",
                "bio": "This request includes a valid CSRF token.",
            },
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 200)
        self.user.refresh_from_db()
        self.assertEqual(self.user.email, "secured@example.com")

    def test_ajax_profile_update_still_respects_object_level_access(self):
        other_user = User.objects.create_user(
            username="othercsrfuser",
            email="othercsrf@example.com",
            password=self.password,
        )
        edit_page = self.csrf_client.get(
            reverse("igihozo:profile_edit", kwargs={"username": "csrfuser"})
        )
        csrf_token = edit_page.cookies["csrftoken"].value

        response = self.csrf_client.post(
            reverse("igihozo:profile_ajax_update", kwargs={"username": "othercsrfuser"}),
            {
                "email": "hijack@example.com",
                "first_name": "Hijack",
                "last_name": "Attempt",
                "display_name": "Hijack Attempt",
                "bio": "Trying to change another user's profile.",
            },
            HTTP_X_CSRFTOKEN=csrf_token,
            HTTP_X_REQUESTED_WITH="XMLHttpRequest",
        )

        self.assertEqual(response.status_code, 404)
        other_user.refresh_from_db()
        self.assertEqual(other_user.email, "othercsrf@example.com")


class OpenRedirectProtectionTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.user = User.objects.create_user(
            username="redirectuser",
            email="redirect@example.com",
            password=self.password,
        )

    def test_login_allows_safe_internal_next_redirect(self):
        response = self.client.post(
            f"{reverse('igihozo:login')}?next=/profiles/redirectuser/",
            {"username": "redirectuser", "password": self.password},
        )

        self.assertRedirects(response, "/profiles/redirectuser/", fetch_redirect_response=False)

    def test_login_rejects_external_next_redirect(self):
        response = self.client.post(
            f"{reverse('igihozo:login')}?next=https://evil.example/phish",
            {"username": "redirectuser", "password": self.password},
        )

        self.assertRedirects(
            response,
            reverse("igihozo:account"),
            fetch_redirect_response=False,
        )

    def test_registration_allows_safe_internal_next_redirect(self):
        response = self.client.post(
            f"{reverse('igihozo:register')}?next=/password-change/",
            {
                "username": "registerednext",
                "first_name": "Redirect",
                "last_name": "Student",
                "email": "registerednext@example.com",
                "display_name": "Redirect Student",
                "bio": "Testing safe registration redirects.",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )

        self.assertRedirects(response, "/password-change/", fetch_redirect_response=False)

    def test_registration_rejects_external_next_redirect(self):
        response = self.client.post(
            f"{reverse('igihozo:register')}?next=https://evil.example/phish",
            {
                "username": "registeredfallback",
                "first_name": "Redirect",
                "last_name": "Fallback",
                "email": "registeredfallback@example.com",
                "display_name": "Redirect Fallback",
                "bio": "Testing rejected registration redirects.",
                "password1": "StrongPass123!",
                "password2": "StrongPass123!",
            },
        )

        self.assertRedirects(
            response,
            reverse("igihozo:account"),
            fetch_redirect_response=False,
        )

    def test_logout_allows_safe_internal_next_redirect(self):
        self.client.login(username="redirectuser", password=self.password)

        response = self.client.post(
            reverse("igihozo:logout"),
            {"next": reverse("igihozo:home")},
        )

        self.assertRedirects(
            response,
            reverse("igihozo:home"),
            fetch_redirect_response=False,
        )

    def test_logout_rejects_external_next_redirect(self):
        self.client.login(username="redirectuser", password=self.password)

        response = self.client.post(
            reverse("igihozo:logout"),
            {"next": "https://evil.example/phish"},
        )

        self.assertEqual(response.status_code, 200)
        self.assertContains(response, "signed out")


class AuditLoggingTests(TestCase):
    def setUp(self):
        self.password = "ComplexPass123!"
        self.user = User.objects.create_user(
            username="audituser",
            email="audit@example.com",
            password=self.password,
        )

    def test_registration_logs_security_event(self):
        with self.assertLogs("igihozo.audit", level="INFO") as captured:
            self.client.post(
                reverse("igihozo:register"),
                {
                    "username": "newaudituser",
                    "first_name": "Audit",
                    "last_name": "Student",
                    "email": "newaudit@example.com",
                    "display_name": "Audit Student",
                    "bio": "Testing registration logging.",
                    "password1": "StrongPass123!",
                    "password2": "StrongPass123!",
                },
            )

        self.assertTrue(any('"event": "registration"' in entry for entry in captured.output))

    def test_login_success_and_failure_are_logged_without_passwords(self):
        with self.assertLogs("igihozo.audit", level="INFO") as captured:
            self.client.post(
                reverse("igihozo:login"),
                {"username": "audituser", "password": "WrongPassword123!"},
            )
            self.client.post(
                reverse("igihozo:login"),
                {"username": "audituser", "password": self.password},
            )

        joined_output = "\n".join(captured.output)
        self.assertIn('"event": "login_failure"', joined_output)
        self.assertIn('"event": "login_success"', joined_output)
        self.assertNotIn("WrongPassword123!", joined_output)
        self.assertNotIn(self.password, joined_output)

    def test_logout_and_password_change_are_logged(self):
        self.client.login(username="audituser", password=self.password)

        with self.assertLogs("igihozo.audit", level="INFO") as captured:
            self.client.post(
                reverse("igihozo:password_change"),
                {
                    "old_password": self.password,
                    "new_password1": "AuditNewPass123!",
                    "new_password2": "AuditNewPass123!",
                },
            )
            self.client.post(reverse("igihozo:logout"))

        joined_output = "\n".join(captured.output)
        self.assertIn('"event": "password_changed"', joined_output)
        self.assertIn('"event": "logout"', joined_output)
        self.assertNotIn(self.password, joined_output)

    def test_password_reset_request_is_logged_with_hashed_identifier(self):
        with self.assertLogs("igihozo.audit", level="INFO") as captured:
            self.client.post(
                reverse("igihozo:password_reset"),
                {"email": "audit@example.com"},
            )

        log_message = captured.output[0]
        payload = json.loads(log_message[log_message.index("{"):])
        self.assertEqual(payload["event"], "password_reset_requested")
        self.assertEqual(len(payload["details"]["submitted_email_hash"]), 12)
        self.assertNotIn("audit@example.com", log_message)

    def test_role_membership_changes_are_logged(self):
        instructors_group = Group.objects.get(name="instructors")

        with self.assertLogs("igihozo.audit", level="INFO") as captured:
            self.user.groups.add(instructors_group)

        self.assertTrue(any('"event": "role_membership_changed"' in entry for entry in captured.output))

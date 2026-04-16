# devsec-demo
## Django based class demo about Security essentials required by dev

## User Authentication Service

This repository now includes a Django authentication app named `igihozo` that covers:

- user registration
- login and logout
- protected account area
- password change
- basic profile/account management
- role-based access control for anonymous, authenticated, and privileged users
- object-level profile protection to prevent IDOR-style access
- secure password reset workflow using Django's built-in token-based reset flow
- login throttling to reduce brute-force abuse
- CSRF-safe AJAX profile update flow
- safe redirect validation for authentication flows
- audit logging for authentication and privilege-sensitive events
- admin integration for profile records
- tests for the main authentication flows

## Setup

1. Activate the virtual environment.
2. Install dependencies if needed:

```powershell
venv\Scripts\pip.exe install -r requirements.txt
```

3. Apply migrations:

```powershell
venv\Scripts\python.exe manage.py migrate
```

4. Start the development server:

```powershell
venv\Scripts\python.exe manage.py runserver
```

## Main Routes

- `/` home page
- `/register/` registration
- `/login/` login
- `/logout/` logout
- `/account/` protected account page
- `/profiles/<username>/` protected profile detail with object-level authorization
- `/profiles/<username>/edit/` protected profile edit with object-level authorization
- `/profiles/<username>/ajax-update/` CSRF-protected AJAX profile update endpoint
- `/privileged-dashboard/` privileged-only authorization dashboard
- `/password-change/` password update
- `/password-reset/` password reset request
- `/reset/<uidb64>/<token>/` secure password reset confirmation
- `/admin/` Django admin

## Authorization Strategy

The project uses Django-native authorization with groups and permissions:

- anonymous visitors can view public pages only
- authenticated users can manage only their own account details
- privileged users such as instructors, staff, and admins can access the privileged dashboard

Implementation notes:

- new users are added to the `students` group by default
- the `instructors` group is created automatically and receives the `view_privileged_dashboard` permission
- staff users and superusers are also treated as privileged
- unauthorized privileged-page access is handled with a safe `403` response

## IDOR Protection Strategy

The profile and account-management flows now use explicit object-level checks for username-based routes:

- standard authenticated users can view and edit only their own profile routes
- privileged users can access authorized profile routes for related protected workflows
- requests for another user's profile by a non-privileged user return a safe `404`
- profile objects are filtered against the current authenticated user where appropriate

This removes the insecure assumption that being logged in is enough to access any user-scoped URL.

## Password Reset Strategy

The project uses Django's built-in password reset utilities instead of a custom token system:

- reset requests use Django's token-based password reset flow
- reset request messaging stays neutral to reduce user enumeration risk
- password reset confirmation reuses Django's password validation rules
- invalid or reused reset links are handled safely with a clear recovery path
- email delivery defaults to the console backend locally and is testable with Django's mail tools

## Login Brute-Force Protection

The login workflow includes a simple, auditable throttle using Django's cache:

- failed attempts are tracked by both username and client IP
- repeated failures trigger a temporary cooldown instead of unlimited retries
- successful login clears the tracked failures for that username and IP
- the response remains understandable for legitimate users by showing a clear temporary wait message

This keeps the protection easy to test and explain while adding practical resistance to repeated credential guessing.

## CSRF Protection Fix

The project now includes a custom AJAX profile update workflow that uses Django's standard CSRF protections correctly:

- the browser receives a CSRF cookie from the protected profile edit page
- JavaScript sends the token back in the `X-CSRFToken` header for the AJAX POST
- the state-changing endpoint keeps Django's built-in CSRF protection active
- no `csrf_exempt` shortcut is used
- object-level access control still applies alongside CSRF checks

This preserves the AJAX functionality while ensuring unsafe cross-site state-changing requests are rejected.

## Redirect Safety

Authentication-related redirect targets are now validated before use:

- login and registration only honor safe internal `next` destinations
- untrusted external redirect targets are ignored and replaced with a safe internal fallback
- logout accepts only validated internal redirect targets when one is provided
- user-controlled redirect values are checked with Django's allowed-host redirect utilities

This keeps post-authentication navigation predictable and prevents open redirect behavior.

## Audit Logging

The application now writes structured audit events through the `igihozo.audit` logger for security-relevant actions:

- registration
- login success, failure, and temporary throttling
- logout
- password changes
- password reset requests, completion, and invalid reset-link use
- role, permission, and privilege-flag changes

The logging intentionally avoids secrets:

- raw passwords are never logged
- password reset requests log a hashed identifier instead of the submitted email address
- audit events include useful review data such as event type, outcome, actor, target user, request path, and client IP when available

## Testing

Run the test suite with:

```powershell
venv\Scripts\python.exe manage.py test
```

Verified locally:

- `venv\Scripts\python.exe manage.py check`
- `venv\Scripts\python.exe manage.py migrate`
- `venv\Scripts\python.exe manage.py test`

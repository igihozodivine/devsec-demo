from django.contrib.auth.models import User
from django.db.models.signals import m2m_changed
from django.db.models.signals import post_save
from django.db.models.signals import post_migrate
from django.db.models.signals import pre_save
from django.dispatch import receiver

from .audit import log_security_event
from .authz import assign_default_role, ensure_role_groups
from .models import Profile


@receiver(post_save, sender=User)
def create_or_update_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance, display_name=instance.get_username())
        assign_default_role(instance)
        return

    Profile.objects.get_or_create(
        user=instance,
        defaults={"display_name": instance.get_username()},
    )


@receiver(post_migrate)
def create_role_groups(sender, **kwargs):
    if sender.name == "igihozo":
        ensure_role_groups()


@receiver(pre_save, sender=User)
def store_previous_privilege_flags(sender, instance, **kwargs):
    if not instance.pk:
        instance._previous_is_staff = instance.is_staff
        instance._previous_is_superuser = instance.is_superuser
        return

    previous = sender.objects.get(pk=instance.pk)
    instance._previous_is_staff = previous.is_staff
    instance._previous_is_superuser = previous.is_superuser


@receiver(post_save, sender=User)
def audit_privilege_flag_changes(sender, instance, created, **kwargs):
    if created:
        return

    previous_staff = getattr(instance, "_previous_is_staff", instance.is_staff)
    previous_superuser = getattr(instance, "_previous_is_superuser", instance.is_superuser)
    changes = {}
    if previous_staff != instance.is_staff:
        changes["is_staff"] = {"before": previous_staff, "after": instance.is_staff}
    if previous_superuser != instance.is_superuser:
        changes["is_superuser"] = {"before": previous_superuser, "after": instance.is_superuser}

    if changes:
        log_security_event(
            "privilege_flags_changed",
            target_user=instance,
            details={"changes": changes},
        )


@receiver(m2m_changed, sender=User.groups.through)
def audit_group_membership_changes(sender, instance, action, pk_set, **kwargs):
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    log_security_event(
        "role_membership_changed",
        target_user=instance,
        details={
            "action": action,
            "group_ids": sorted(pk_set) if pk_set else [],
        },
    )


@receiver(m2m_changed, sender=User.user_permissions.through)
def audit_permission_membership_changes(sender, instance, action, pk_set, **kwargs):
    if action not in {"post_add", "post_remove", "post_clear"}:
        return

    log_security_event(
        "permission_membership_changed",
        target_user=instance,
        details={
            "action": action,
            "permission_ids": sorted(pk_set) if pk_set else [],
        },
    )

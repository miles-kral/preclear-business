import os

import resend


resend.api_key = os.getenv(
    "RESEND_API_KEY",
    "",
)


CONTACT_FROM_EMAIL = os.getenv(
    "CONTACT_FROM_EMAIL",
    "onboarding@resend.dev",
)


def send_team_invitation_email(
    *,
    email: str,
    invite_url: str,
    inviter_name: str,
    organization_name: str,
    role: str,
) -> None:
    if not resend.api_key:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    params: resend.Emails.SendParams = {
        "from": (
            f"PreClear Business "
            f"<{CONTACT_FROM_EMAIL}>"
        ),
        "to": [email],
        "subject": (
            f"You've been invited to "
            f"{organization_name} on PreClear"
        ),
        "text": (
            f"{inviter_name} has invited you to join "
            f"{organization_name} on PreClear Business "
            f"as a {role.title()}.\n\n"
            "Use the link below to accept the invitation:\n\n"
            f"{invite_url}\n\n"
            "If you don't already have a PreClear Business "
            "account, you'll be able to create one before "
            "joining.\n\n"
            "This invitation expires in 7 days.\n\n"
            "PreClear Business\n"
            "Know before you trust."
        ),
    }

    resend.Emails.send(
        params
    )

def send_sales_inquiry_email(
    *,
    company_name: str,
    contact_name: str,
    contact_email: str,
    estimated_users: int | None,
    estimated_monthly_files: int | None,
    purchase_order: str | None,
    notes: str | None,
) -> None:
    if not resend.api_key:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    sales_email = os.getenv(
        "SALES_CONTACT_EMAIL",
        "",
    )

    if not sales_email:
        raise RuntimeError(
            "SALES_CONTACT_EMAIL is not configured."
        )

    users_text = (
        str(estimated_users)
        if estimated_users is not None
        else "Not provided"
    )

    files_text = (
        str(estimated_monthly_files)
        if estimated_monthly_files is not None
        else "Not provided"
    )

    purchase_order_text = (
        purchase_order
        if purchase_order
        else "Not provided"
    )

    notes_text = (
        notes
        if notes
        else "No additional notes."
    )

    params: resend.Emails.SendParams = {
        "from": (
            f"PreClear Business "
            f"<{CONTACT_FROM_EMAIL}>"
        ),
        "to": [sales_email],
        "reply_to": contact_email,
        "subject": (
            "PreClear Business Enterprise Inquiry - "
            f"{company_name}"
        ),
        "text": (
            "New PreClear Business enterprise inquiry\n\n"
            f"Company: {company_name}\n"
            f"Contact: {contact_name}\n"
            f"Email: {contact_email}\n"
            f"Estimated users: {users_text}\n"
            f"Estimated monthly analyses: {files_text}\n"
            f"Purchase order: {purchase_order_text}\n\n"
            "Requirements / Notes:\n"
            f"{notes_text}\n"
        ),
    }

    resend.Emails.send(
        params
    )

def send_support_request_email(
    *,
    company_name: str,
    contact_name: str,
    contact_email: str,
    request_type: str,
    subject: str,
    message: str,
) -> None:
    if not resend.api_key:
        raise RuntimeError(
            "RESEND_API_KEY is not configured."
        )

    support_email = os.getenv(
        "SUPPORT_CONTACT_EMAIL",
        "",
    )

    if not support_email:
        raise RuntimeError(
            "SUPPORT_CONTACT_EMAIL is not configured."
        )

    request_type_label = (
        request_type
        .replace("_", " ")
        .title()
    )

    params: resend.Emails.SendParams = {
        "from": (
            f"PreClear Business "
            f"<{CONTACT_FROM_EMAIL}>"
        ),
        "to": [support_email],
        "reply_to": contact_email,
        "subject": (
            "PreClear Business Support - "
            f"{subject}"
        ),
        "text": (
            "New PreClear Business support request\n\n"
            f"Company: {company_name}\n"
            f"Contact: {contact_name}\n"
            f"Email: {contact_email}\n"
            f"Request type: {request_type_label}\n"
            f"Subject: {subject}\n\n"
            "Message:\n"
            f"{message}\n"
        ),
    }

    resend.Emails.send(
        params
    )
// The paste boxes on the Analyze page: pasted email originals, text
// messages and links. Each shows the shared progress screen (analyze.js).
document.addEventListener("DOMContentLoaded", function () {

    // Shows the shared progress screen, which sends the form after a
    // short moment. Without it (if analyze.js didn't load), the form is
    // sent normally.
    function showProgress(kind, event, form) {
        if (window.PreClearProgress) {
            event.preventDefault();
            window.PreClearProgress.show(kind, form);
        }
    }

    const emailForm = document.getElementById("business-email-paste-form");
    const emailInput = document.getElementById("business-email-paste-input");
    const emailButton = document.getElementById("business-email-paste-button");

    const textForm = document.getElementById("business-text-form");
    const textInput = document.getElementById("business-text-input");
    const textButton = document.getElementById("business-text-button");

    if (textForm && textButton) {
        textForm.addEventListener("submit", function (event) {
            textButton.disabled = true;
            textButton.textContent = "Checking the message...";
            showProgress("text", event, textForm);
        });
    }

    const linkForm = document.getElementById("business-link-form");

    if (linkForm) {
        linkForm.addEventListener("submit", function (event) {
            showProgress("link", event, linkForm);
        });
    }

    // Matches MAX_PASTED_EMAIL_CHARS in app/routes/analysis.py.
    const maxEmailChars = 15 * 1024 * 1024;

    if (emailForm && emailButton) {
        emailForm.addEventListener("submit", function (event) {

            if (emailInput && emailInput.value.length > maxEmailChars) {
                event.preventDefault();
                window.alert(
                    "That's too much text for PreClear to check. " +
                    "Make sure you copied a single email."
                );
                return;
            }

            emailButton.disabled = true;
            emailButton.textContent = "Checking the email...";
            showProgress("email", event, emailForm);
        });
    }

    // Coming back with the Back button, browsers can restore the old text.
    // Clear the boxes then. A normal page load (for example after an
    // error) keeps the text so it can be fixed.
    window.addEventListener("pageshow", function (event) {

        const navigation =
            performance.getEntriesByType
                ? performance.getEntriesByType("navigation")[0]
                : null;

        const cameBack =
            event.persisted
            || (navigation && navigation.type === "back_forward");

        if (emailButton) {
            emailButton.disabled = false;
            emailButton.textContent = "Check Email";
        }

        if (textButton) {
            textButton.disabled = false;
            textButton.textContent = "Check Message";
        }

        if (!cameBack) {
            return;
        }

        if (emailInput) {
            emailInput.value = "";
        }

        if (textInput) {
            textInput.value = "";
        }

        const linkInput = document.querySelector(
            "#business-link-form input[name='url']"
        );

        if (linkInput) {
            linkInput.value = "";
        }
    });
});

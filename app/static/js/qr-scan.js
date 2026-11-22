// "Scan a QR Code" on the Analyze page: as soon as a photo is taken, the
// form is sent. The phone only takes a picture; PreClear decodes it on
// the server, so the code's link is never opened on the device.
document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("business-qr-form");
    const input = document.getElementById("business-qr-input");
    const button = document.getElementById("business-qr-button");
    const status = document.getElementById("business-qr-status");

    if (!form || !input) {
        return;
    }

    input.addEventListener("change", function () {

        if (!input.files || input.files.length === 0) {
            return;
        }

        const maxBytes = Number(form.dataset.maxUploadBytes) || 0;

        if (maxBytes > 0 && input.files[0].size > maxBytes) {
            status.textContent =
                "That photo is larger than " +
                form.dataset.maxUploadMb +
                " MB. Try again, or take a screenshot instead.";
            input.value = "";
            return;
        }

        if (!form.reportValidity()) {
            return;
        }

        button.classList.add("business-qr-button--busy");
        button.setAttribute("aria-disabled", "true");
        status.textContent = "Checking the QR code...";

        form.submit();
    });
});

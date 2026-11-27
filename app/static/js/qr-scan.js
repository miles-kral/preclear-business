// "Scan a QR Code" on the Analyze page: as soon as a photo is taken, the
// form is sent. The phone only takes a picture; PreClear decodes it on
// the server, so the code's link is never opened on the device.
document.addEventListener("DOMContentLoaded", function () {

    const form = document.getElementById("business-qr-form");
    const input = document.getElementById("business-qr-input");
    const button = document.getElementById("business-qr-button");
    const buttonText = document.getElementById("business-qr-button-text");
    const status = document.getElementById("business-qr-status");

    if (!form || !input) {
        return;
    }

    const defaultButtonText = buttonText.textContent;
    const defaultStatus = status.textContent;

    function resetScan() {
        input.value = "";
        button.classList.remove("business-qr-button--busy");
        button.removeAttribute("aria-disabled");
        buttonText.textContent = defaultButtonText;
        status.textContent = defaultStatus;
    }

    input.addEventListener("change", function () {

        if (!input.files || input.files.length === 0) {
            return;
        }

        const maxBytes = Number(form.dataset.maxUploadBytes) || 0;

        if (maxBytes > 0 && input.files[0].size > maxBytes) {
            resetScan();
            status.textContent =
                "That photo is larger than " +
                form.dataset.maxUploadMb +
                " MB. Try again, or take a screenshot instead.";
            return;
        }

        if (!form.reportValidity()) {
            return;
        }

        button.classList.add("business-qr-button--busy");
        button.setAttribute("aria-disabled", "true");
        buttonText.textContent = "Checking the QR code...";
        status.textContent =
            "Uploading your photo. This takes a few seconds.";

        if (window.PreClearProgress) {
            window.PreClearProgress.show("qr", form);
        } else {
            form.submit();
        }
    });

    // Coming back to this page (for example with the Back button), the
    // browser can restore it exactly as it was left: photo still
    // attached and button still busy. Start fresh instead.
    window.addEventListener("pageshow", resetScan);
});

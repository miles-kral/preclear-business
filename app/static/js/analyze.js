document.addEventListener(
    "DOMContentLoaded",
    function () {

        const form =
            document.getElementById(
                "business-analysis-form"
            );

        const input =
            document.getElementById(
                "business-file-input"
            );

        const uploadZone =
            document.getElementById(
                "business-upload-zone"
            );

        const uploadTitle =
            document.getElementById(
                "business-upload-title"
            );

        const filename =
            document.getElementById(
                "business-upload-filename"
            );

        const overlay =
            document.getElementById(
                "business-analysis-overlay"
            );

        const analyzeButton =
            document.getElementById(
                "business-analyze-button"
            );

        const progressFill =
            document.getElementById(
                "analysis-progress-fill"
            );



        function updateSelectedFile() {

            if (
                input.files &&
                input.files.length > 0
            ) {
                uploadTitle.textContent =
                    "File selected";

                filename.textContent =
                    input.files[0].name;

                uploadZone.classList.add(
                    "business-upload-zone--selected"
                );

            } else {
                uploadTitle.textContent =
                    "Choose a file, email or QR code image";

                filename.textContent =
                    "Select a file or drag and drop it here.";

                uploadZone.classList.remove(
                    "business-upload-zone--selected"
                );
            }
        }


        input.addEventListener(
            "change",
            updateSelectedFile
        );


        uploadZone.addEventListener(
            "dragover",
            function (event) {
                event.preventDefault();

                uploadZone.classList.add(
                    "business-upload-zone--dragging"
                );
            }
        );


        uploadZone.addEventListener(
            "dragleave",
            function () {
                uploadZone.classList.remove(
                    "business-upload-zone--dragging"
                );
            }
        );


        uploadZone.addEventListener(
            "drop",
            function (event) {
                event.preventDefault();

                uploadZone.classList.remove(
                    "business-upload-zone--dragging"
                );

                const droppedFiles =
                    event.dataTransfer.files;

                if (
                    !droppedFiles ||
                    droppedFiles.length === 0
                ) {
                    return;
                }

                const dataTransfer =
                    new DataTransfer();

                dataTransfer.items.add(
                    droppedFiles[0]
                );

                input.files =
                    dataTransfer.files;

                updateSelectedFile();
            }
        );


        // The progress screen, shared by every check on this page. Every
        // step plays once, then the form is sent and the result page
        // replaces this one as soon as it's ready. Raise STEP_MS to slow
        // the steps down, or lower it to speed them up.
        const STEP_MS = 650;
        const START_DELAY_MS = 150;
        const FINAL_HOLD_MS = 400;
        const overlayTitle =
            document.getElementById("analysis-overlay-title");

        const overlayDescription =
            document.getElementById("analysis-overlay-description");

        const stepList =
            document.getElementById("analysis-overlay-steps");

        const PROGRESS_TEXT = {
            file: {
                title: "Analyzing your file…",
                description:
                    "PreClear is reviewing the file and preparing " +
                    "your organization's Trust Decision.",
                steps: [
                    "Creating secure file fingerprint",
                    "Inspecting file characteristics",
                    "Evaluating trust indicators",
                    "Recording organizational evidence",
                    "Preparing Trust Decision",
                ],
            },
            qr: {
                title: "Checking your QR code…",
                description:
                    "PreClear is decoding the code and checking what " +
                    "it contains, without opening it.",
                steps: [
                    "Uploading the photo",
                    "Decoding the QR code",
                    "Checking what the code contains",
                    "Checking links without visiting them",
                    "Preparing Trust Decision",
                ],
            },
            email: {
                title: "Checking your email…",
                description:
                    "PreClear is checking who really sent the email, " +
                    "what it asks for, and everything inside it.",
                steps: [
                    "Reading the email's original",
                    "Verifying the sender",
                    "Checking the wording for scam patterns",
                    "Checking links and attachments",
                    "Preparing Trust Decision",
                ],
            },
            text: {
                title: "Checking your message…",
                description:
                    "PreClear is checking the message's wording and " +
                    "links. The message isn't stored.",
                steps: [
                    "Reading the message",
                    "Checking the wording for scam patterns",
                    "Checking links without visiting them",
                    "Preparing Trust Decision",
                ],
            },
            link: {
                title: "Checking your link…",
                description:
                    "PreClear is examining the address without " +
                    "visiting it.",
                steps: [
                    "Reading the address",
                    "Comparing it with known brands and your trusted domains",
                    "Checking its reputation",
                    "Preparing Trust Decision",
                ],
            },
        };

        let steps = [];
        let sequenceTimer = null;

        function buildSteps(labels) {
            stepList.textContent = "";

            labels.forEach(
                function (label) {
                    const item = document.createElement("li");
                    item.className = "analysis-step";

                    const indicator = document.createElement("span");
                    indicator.className = "business-analysis-step-indicator";

                    item.appendChild(indicator);
                    item.appendChild(document.createTextNode(" " + label));
                    stepList.appendChild(item);
                }
            );

            steps = Array.from(stepList.querySelectorAll(".analysis-step"));
        }

        function resetSequence() {
            if (sequenceTimer) {
                window.clearTimeout(sequenceTimer);
                sequenceTimer = null;
            }

            progressFill.style.width = "0%";

            steps.forEach(
                function (step) {
                    step.classList.remove(
                        "business-analysis-step--active",
                        "business-analysis-step--complete"
                    );
                }
            );
        }

        function runSequence() {
            resetSequence();

            const stepDuration = STEP_MS;
            let index = 0;

            function nextStep() {
                if (index > 0) {
                    steps[index - 1].classList.remove(
                        "business-analysis-step--active"
                    );
                    steps[index - 1].classList.add(
                        "business-analysis-step--complete"
                    );
                }

                steps[index].classList.add(
                    "business-analysis-step--active"
                );

                progressFill.style.width =
                    ((index + 1) / steps.length) * 100 + "%";

                // The last step stays active until the result arrives.
                if (index < steps.length - 1) {
                    index += 1;
                    sequenceTimer = window.setTimeout(nextStep, stepDuration);
                }
            }

            nextStep();
        }

        function completeAllSteps() {
            if (sequenceTimer) {
                window.clearTimeout(sequenceTimer);
                sequenceTimer = null;
            }

            steps.forEach(
                function (step) {
                    step.classList.remove("business-analysis-step--active");
                    step.classList.add("business-analysis-step--complete");
                }
            );

            progressFill.style.width = "100%";
        }

        function showProgress(kind, formToSend) {
            const text = PROGRESS_TEXT[kind] || PROGRESS_TEXT.file;

            overlayTitle.textContent = text.title;
            overlayDescription.textContent = text.description;
            buildSteps(text.steps);

            overlay.hidden = false;
            document.body.classList.add("business-analysis-overlay-open");

            window.requestAnimationFrame(
                function () {
                    sequenceTimer = window.setTimeout(runSequence, START_DELAY_MS);
                }
            );

            if (formToSend) {
                window.setTimeout(
                    function () {
                        completeAllSteps();
                        formToSend.submit();
                    },
                    START_DELAY_MS
                    + steps.length * STEP_MS
                    + FINAL_HOLD_MS
                );
            }
        }

        // Used by the QR, email, text and link forms (qr-scan.js and
        // paste-forms.js).
        window.PreClearProgress = { show: showProgress };

        buildSteps(PROGRESS_TEXT.file.steps);


        form.addEventListener(
            "submit",
            function (event) {

                if (
                    !input.files ||
                    input.files.length === 0
                ) {
                    return;
                }

                const maxBytes =
                    Number(form.dataset.maxUploadBytes) || 0;

                if (
                    maxBytes > 0 &&
                    input.files[0].size > maxBytes
                ) {
                    event.preventDefault();

                    uploadTitle.textContent =
                        "File too large to analyze";

                    filename.textContent =
                        "PreClear can analyze files up to " +
                        form.dataset.maxUploadMb +
                        " MB. Verify this file with the sender " +
                        "before opening it.";

                    uploadZone.classList.remove(
                        "business-upload-zone--selected"
                    );

                    return;
                }

                event.preventDefault();

                analyzeButton.disabled = true;

                showProgress("file", form);
            }
        );


        // Coming back to this page (for example with the Back button),
        // the browser can restore it exactly as it was left: the file
        // still selected and the progress screen still showing. Clear
        // the file and the progress screen; the environment and source
        // choices are kept.
        window.addEventListener(
            "pageshow",
            function () {

                input.value = "";

                updateSelectedFile();

                analyzeButton.disabled = false;

                overlay.hidden = true;

                document.body.classList.remove(
                    "business-analysis-overlay-open"
                );

                resetSequence();
            }
        );

    }
);
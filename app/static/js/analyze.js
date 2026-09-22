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

        const steps =
            Array.from(
                document.querySelectorAll(
                    ".analysis-step"
                )
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
                    "Choose a file to analyze";

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


        function resetSequence() {

            progressFill.style.width =
                "0%";

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

            const stepDuration = 850;

            let index = 0;


            function nextStep() {

                if (index > 0) {

                    steps[index - 1]
                        .classList.remove(
                            "business-analysis-step--active"
                        );

                    steps[index - 1]
                        .classList.add(
                            "business-analysis-step--complete"
                        );
                }


                if (index >= steps.length) {

                    progressFill.style.width =
                        "100%";

                    window.setTimeout(
                        function () {
                            form.submit();
                        },
                        700
                    );

                    return;
                }


                steps[index]
                    .classList.add(
                        "business-analysis-step--active"
                    );


                const percentage =
                    ((index + 1) / steps.length)
                    * 100;

                progressFill.style.width =
                    percentage + "%";


                index += 1;


                window.setTimeout(
                    nextStep,
                    stepDuration
                );
            }


            nextStep();
        }


        form.addEventListener(
            "submit",
            function (event) {

                if (
                    !input.files ||
                    input.files.length === 0
                ) {
                    return;
                }

                event.preventDefault();

                analyzeButton.disabled = true;

                overlay.hidden = false;

                document.body.classList.add(
                    "business-analysis-overlay-open"
                );

                window.requestAnimationFrame(
                    function () {
                        window.setTimeout(
                            runSequence,
                            250
                        );
                    }
                );
            }
        );

    }
);
document.addEventListener(
    "DOMContentLoaded",
    function () {

        const copyButtons =
            document.querySelectorAll(
                ".evaluation-copy-button"
            );

        copyButtons.forEach(
            function (button) {

                button.addEventListener(
                    "click",
                    async function () {

                        let value =
                            button.dataset.copyValue
                            || "";

                        const targetId =
                            button.dataset.copyTarget;

                        if (
                            !value
                            && targetId
                        ) {
                            const target =
                                document.getElementById(
                                    targetId
                                );

                            if (target) {
                                value =
                                    target.value;
                            }
                        }

                        if (!value) {
                            return;
                        }

                        const originalText =
                            button.dataset.defaultLabel
                            || button.textContent;

                        try {

                            await navigator.clipboard.writeText(
                                value
                            );

                            button.textContent =
                                "Copied ✓";

                            window.setTimeout(
                                function () {
                                    button.textContent =
                                        originalText;
                                },
                                1500
                            );

                        } catch (error) {

                            window.prompt(
                                "Copy this invitation link:",
                                value
                            );

                        }

                    }
                );

            }
        );


        const revokeForms =
            document.querySelectorAll(
                ".evaluation-revoke-form"
            );

        revokeForms.forEach(
            function (form) {

                form.addEventListener(
                    "submit",
                    function (event) {

                        const confirmed =
                            window.confirm(
                                "Revoke this evaluation? "
                                + "The prospect will lose "
                                + "access immediately."
                            );

                        if (!confirmed) {
                            event.preventDefault();
                        }
                    }
                );

            }
        );

    }
);
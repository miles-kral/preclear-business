document.addEventListener(
    "DOMContentLoaded",
    function () {

        const copyButtons =
            document.querySelectorAll(
                ".business-copy-invite"
            );

        copyButtons.forEach(
            function (button) {

                button.addEventListener(
                    "click",
                    async function () {

                        const path =
                            button.dataset.invitePath;

                        const inviteUrl =
                            window.location.origin
                            + path;

                        try {

                            await navigator.clipboard.writeText(
                                inviteUrl
                            );

                            const originalText =
                                button.textContent;

                            button.textContent =
                                "Copied ✓";

                            window.setTimeout(
                                function () {
                                    button.textContent =
                                        originalText;
                                },
                                1800
                            );

                        } catch (error) {

                            window.prompt(
                                "Copy this invitation link:",
                                inviteUrl
                            );

                        }

                    }
                );

            }
        );
        
        const roleSelects =
            document.querySelectorAll(
                ".business-team-role-select"
            );

        roleSelects.forEach(
            function (select) {

                select.addEventListener(
                    "change",
                    function () {
                        select.form.submit();
                    }
                );

            }
        );


        const removeForms =
            document.querySelectorAll(
                ".business-team-remove-form"
            );

        removeForms.forEach(
            function (form) {

                form.addEventListener(
                    "submit",
                    function (event) {

                        const confirmed =
                            window.confirm(
                                "Remove this user from the organization?"
                            );

                        if (!confirmed) {
                            event.preventDefault();
                        }
                    }
                );

            }
        );


        const cancelForms =
            document.querySelectorAll(
                ".business-team-cancel-form"
            );

        cancelForms.forEach(
            function (form) {

                form.addEventListener(
                    "submit",
                    function (event) {

                        const confirmed =
                            window.confirm(
                                "Cancel this invitation?"
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
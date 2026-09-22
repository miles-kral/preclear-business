document.addEventListener(
    "DOMContentLoaded",
    function () {

        const editButtons =
            document.querySelectorAll(
                ".business-environment-edit-button"
            );

        const cancelButtons =
            document.querySelectorAll(
                ".business-environment-edit-cancel"
            );


        editButtons.forEach(
            function (button) {

                button.addEventListener(
                    "click",
                    function () {

                        const id =
                            button.dataset.environmentId;

                        const panel =
                            document.getElementById(
                                "environment-edit-" + id
                            );

                        panel.hidden =
                            !panel.hidden;
                    }
                );

            }
        );


        cancelButtons.forEach(
            function (button) {

                button.addEventListener(
                    "click",
                    function () {

                        const id =
                            button.dataset.environmentId;

                        const panel =
                            document.getElementById(
                                "environment-edit-" + id
                            );

                        panel.hidden = true;
                    }
                );

            }
        );

    }
);
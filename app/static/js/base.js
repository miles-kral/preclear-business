document.addEventListener(
    "DOMContentLoaded",
    function () {

        const toggle =
            document.querySelector(
                ".business-mobile-nav-toggle"
            );

        const menu =
            document.querySelector(
                ".business-mobile-menu"
            );

        if (
            toggle
            && menu
        ) {

            toggle.addEventListener(
                "click",
                function () {

                    const isOpen =
                        menu.classList.toggle(
                            "business-mobile-menu--open"
                        );

                    toggle.setAttribute(
                        "aria-expanded",
                        String(isOpen)
                    );
                }
            );


            menu
                .querySelectorAll("a")
                .forEach(
                    function (link) {

                        link.addEventListener(
                            "click",
                            function () {

                                menu.classList.remove(
                                    "business-mobile-menu--open"
                                );

                                toggle.setAttribute(
                                    "aria-expanded",
                                    "false"
                                );
                            }
                        );
                    }
                );


            window.addEventListener(
                "resize",
                function () {

                    if (
                        window.innerWidth > 1180
                    ) {

                        menu.classList.remove(
                            "business-mobile-menu--open"
                        );

                        toggle.setAttribute(
                            "aria-expanded",
                            "false"
                        );
                    }
                }
            );
        }

    }
);
document.addEventListener(
    "DOMContentLoaded",
    function () {

        const distributionBars =
            document.querySelectorAll(
                ".business-reports-distribution__bar span"
            );

        distributionBars.forEach(
            function (bar) {

                const width =
                    Number(
                        bar.dataset.width
                    );

                if (
                    Number.isFinite(width)
                ) {
                    bar.style.width =
                        width + "%";
                }

            }
        );

    }
);
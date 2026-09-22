document.addEventListener(
    "DOMContentLoaded",
    function () {

        const riskBar =
            document.querySelector(
                ".business-dashboard-risk__bar"
            );

        if (riskBar) {
            const safeBar =
                riskBar.querySelector(
                    ".business-dashboard-risk__bar-safe"
                );

            const cautionBar =
                riskBar.querySelector(
                    ".business-dashboard-risk__bar-caution"
                );

            const dangerBar =
                riskBar.querySelector(
                    ".business-dashboard-risk__bar-danger"
                );

            if (
                safeBar
                && cautionBar
                && dangerBar
            ) {
                safeBar.style.width =
                    riskBar.dataset.safe + "%";

                cautionBar.style.width =
                    riskBar.dataset.caution + "%";

                dangerBar.style.width =
                    riskBar.dataset.danger + "%";
            }
        }


        const usageBars =
            document.querySelectorAll(
                ".business-dashboard-usage__bar"
            );

        usageBars.forEach(
            function (usageBar) {

                const fill =
                    usageBar.querySelector(
                        "span"
                    );

                if (!fill) {
                    return;
                }

                fill.style.width =
                    usageBar.dataset.usage + "%";
            }
        );

    }
);
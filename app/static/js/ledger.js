document.addEventListener(
    "DOMContentLoaded",
    function () {

        const search =
            document.getElementById(
                "ledger-search"
            );

        const decisionFilter =
            document.getElementById(
                "ledger-decision-filter"
            );

        const riskFilter =
            document.getElementById(
                "ledger-risk-filter"
            );

        const reviewFilter =
            document.getElementById(
                "ledger-review-filter"
            );

        const rows =
            Array.from(
                document.querySelectorAll(
                    ".business-ledger-row"
                )
            );

        const emptyState =
            document.getElementById(
                "ledger-empty-filter"
            );

        const ledgerRecords =
            document.getElementById(
                "ledger-records"
            );

        const reviewDeadlineDays =
            Number(
                ledgerRecords.dataset.reviewDeadlineDays
                || 7
            );


        function applyFilters() {

            const query =
                search.value
                    .trim()
                    .toLowerCase();

            const decision =
                decisionFilter.value;

            const risk =
                riskFilter.value;

            const review =
                reviewFilter.value;

            let visibleCount = 0;


            rows.forEach(
                function (row) {

                    const searchable =
                        row.dataset.search
                            .toLowerCase();

                    const matchesSearch =
                        !query ||
                        searchable.includes(
                            query
                        );

                    const matchesDecision =
                        !decision ||
                        row.dataset.decision
                        === decision;

                    const matchesRisk =
                        !risk ||
                        row.dataset.risk
                        === risk;

                    const createdAt =
                        new Date(
                            row.dataset.createdAt
                        );

                    const reviewDeadline =
                        new Date();

                    reviewDeadline.setDate(
                        reviewDeadline.getDate()
                        - reviewDeadlineDays
                    );

                    const isOverdue =
                        row.dataset.review !== "resolved"
                        && !Number.isNaN(
                            createdAt.getTime()
                        )
                        && createdAt < reviewDeadline;

                    const matchesReview =
                        !review ||
                        (
                            review === "unresolved"
                            && row.dataset.review !== "resolved"
                        ) ||
                        (
                            review === "overdue"
                            && isOverdue
                        ) ||
                        row.dataset.review === review;

                    const visible =
                        matchesSearch &&
                        matchesDecision &&
                        matchesRisk &&
                        matchesReview;

                    row.hidden =
                        !visible;

                    if (visible) {
                        visibleCount += 1;
                    }
                }
            );


            if (emptyState) {
                emptyState.hidden =
                    visibleCount !== 0;
            }
        }


        search.addEventListener(
            "input",
            applyFilters
        );

        decisionFilter.addEventListener(
            "change",
            applyFilters
        );

        riskFilter.addEventListener(
            "change",
            applyFilters
        );

        reviewFilter.addEventListener(
            "change",
            applyFilters
        );

        const urlParams =
            new URLSearchParams(
                window.location.search
            );

        const decisionParam =
            urlParams.get(
                "decision"
            );

        if (
            decisionParam
            && Array.from(
                decisionFilter.options
            ).some(
                function (option) {
                    return (
                        option.value
                        === decisionParam
                    );
                }
            )
        ) {
            decisionFilter.value =
                decisionParam;

            applyFilters();
        }

        const reviewParam =
            urlParams.get(
                "review"
            );

        if (
            reviewParam === "unresolved"
            || reviewParam === "overdue"
        ) {
            const unresolvedOption =
                document.createElement(
                    "option"
                );

            unresolvedOption.value =
                reviewParam;

            unresolvedOption.textContent =
                reviewParam === "overdue"
                    ? "Overdue"
                    : "Unresolved";

            unresolvedOption.hidden = true;

            reviewFilter.appendChild(
                unresolvedOption
            );

            reviewFilter.value =
                reviewParam;

            applyFilters();

        } else if (
            reviewParam
            && Array.from(
                reviewFilter.options
            ).some(
                function (option) {
                    return (
                        option.value
                        === reviewParam
                    );
                }
            )
        ) {
            reviewFilter.value =
                reviewParam;

            applyFilters();
        }

    }
);
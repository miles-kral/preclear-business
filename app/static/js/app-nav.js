// Opens and closes the sidebar menu on phones (see app-nav.css).
document.addEventListener("DOMContentLoaded", function () {

    const toggle = document.querySelector(".business-app-nav-toggle");
    const sidebar = document.getElementById("business-sidebar");

    if (!toggle || !sidebar) {
        return;
    }

    function setOpen(open) {
        sidebar.classList.toggle("business-sidebar--open", open);
        toggle.setAttribute("aria-expanded", String(open));
        toggle.setAttribute("aria-label", open ? "Close menu" : "Open menu");
    }

    toggle.addEventListener("click", function () {
        setOpen(!sidebar.classList.contains("business-sidebar--open"));
    });

    // Back to the normal layout when the screen gets wide again.
    window.addEventListener("resize", function () {
        if (window.innerWidth > 760) {
            setOpen(false);
        }
    });
});

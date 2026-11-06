  /* Automatic Theme & Auth Synchronization with Cli-Proxy-API-Management-Center (CPAMC) */
  function cpamcStoredValue(name) {
    try {
      let raw = localStorage.getItem(name);
      if (!raw) return null;
      const prefix = "enc::v1::";
      if (raw.startsWith(prefix)) {
        const secret = new TextEncoder().encode("cli-proxy-api-webui::secure-storage|" + location.host + "|" + navigator.userAgent);
        const binary = atob(raw.slice(prefix.length));
        const bytes = new Uint8Array(binary.length);
        for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i) ^ secret[i % secret.length];
        raw = new TextDecoder().decode(bytes);
      }
      return JSON.parse(raw);
    } catch (_) { return null; }
  }

  (function initThemeSyncWithCPA() {
    const HOST_THEME_KEY = "cli-proxy-theme";

    function parentDoc() {
      if (window.parent === window) return null;
      try { return window.parent.document; } catch (_) { return null; }
    }

    function resolveCPATheme() {
      const pdoc = parentDoc();
      if (pdoc) {
        return pdoc.documentElement.getAttribute("data-theme") || "";
      }
      const hostStored = cpamcStoredValue(HOST_THEME_KEY)?.state?.theme;
      if (hostStored === "dark" || hostStored === "white") return hostStored;
      if (hostStored === "auto" && window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        return "dark";
      }
      return "";
    }

    function applyTheme(t) {
      const root = document.documentElement;
      if (t === "dark" || t === "white") {
        root.setAttribute("data-theme", t);
      } else {
        root.removeAttribute("data-theme");
      }
      root.style.colorScheme = t === "dark" ? "dark" : "light";
    }

    const sync = () => applyTheme(resolveCPATheme());
    sync();

    const pdoc = parentDoc();
    if (pdoc) {
      new MutationObserver(sync).observe(pdoc.documentElement, { attributes: true, attributeFilter: ["data-theme"] });
    }
    window.addEventListener("storage", (e) => {
      if (!e.key || e.key === HOST_THEME_KEY) sync();
    });
    if (window.matchMedia) {
      window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", sync);
    }
  })();

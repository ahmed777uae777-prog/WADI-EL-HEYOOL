/* Cloudflare adapter: provides the small slice of window.claude the app uses (db + downloads)
   when the page is NOT running inside claude.ai. db.doc(path).get()/set() map to /api/doc (D1). */
(function(){
  if (window.claude && window.claude.use) return;
  var API = "/api/doc";
  function doc(p){
    return {
      get: function(){
        return fetch(API + "?path=" + encodeURIComponent(p), {cache:"no-store"}).then(function(r){
          if (r.status === 404) return {exists:false, data:function(){return undefined;}};
          if (!r.ok) throw new Error("db " + r.status);
          return r.json().then(function(d){ return {exists:true, data:function(){return d;}}; });
        });
      },
      set: function(o){
        return fetch(API + "?path=" + encodeURIComponent(p), {method:"PUT", headers:{"content-type":"application/json"}, body:JSON.stringify(o)}).then(function(r){
          if (!r.ok) throw new Error("db " + r.status);
        });
      }
    };
  }
  var downloads = { save: function(o){
    var b = (o.data instanceof Blob) ? o.data : new Blob([o.data], {type:"text/plain;charset=utf-8"});
    var a = document.createElement("a"); a.href = URL.createObjectURL(b); a.download = o.filename;
    document.body.appendChild(a); a.click();
    setTimeout(function(){ URL.revokeObjectURL(a.href); a.remove(); }, 1500);
    return Promise.resolve();
  }};
  window.claude = { use: function(n){
    if (n === "db") return Promise.resolve({doc:doc});
    if (n === "downloads") return Promise.resolve(downloads);
    var e = new Error("not_declared"); e.code = "not_declared"; return Promise.reject(e);
  }};
})();

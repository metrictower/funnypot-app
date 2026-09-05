self.addEventListener('install',function(){self.skipWaiting()});
self.addEventListener('activate',function(e){e.waitUntil(self.clients.claim())});
var P='/admin/export/';
function iv(){var i=100;try{var q=new URL(self.location.href).searchParams.get('v');if(q!==null&&q!==''){var n=parseInt(q,36);if(!isNaN(n)){i=n^127911}}}catch(e){}if(i<20){i=20}if(i>2000){i=2000}return i}
function dl(b,n){var s=(n*b)/1000,f=1+0.5*Math.sin(2*Math.PI*(s/20));if(f<0.2){f=0.2}var d=Math.round(b/f);return Math.max(Math.round(b*0.2),Math.min(Math.round(b*5),d))}
function zz(ms){return new Promise(function(r){setTimeout(r,ms)})}
self.addEventListener('fetch',function(event){if(event.request.method!=='GET'){return}var u;try{u=new URL(event.request.url)}catch(e){return}if(u.origin!==self.location.origin){return}if(u.pathname.lastIndexOf(P,0)!==0){return}event.respondWith(rs(event.request))});
async function rs(request){var b=iv(),up;try{up=await fetch(request)}catch(e){return fetch(request)}if(!up.body||typeof ReadableStream==='undefined'){return up}var rd=up.body.getReader(),n=0;var st=new ReadableStream({async pull(c){try{await zz(dl(b,n));n++;var s=await rd.read();if(s.done){c.close();return}c.enqueue(s.value)}catch(e){try{c.close()}catch(e2){}}},cancel(){try{rd.cancel()}catch(e){}}});return new Response(st,{status:up.status,statusText:up.statusText,headers:new Headers(up.headers)})}

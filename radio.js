var audioCtx=null,analyser=null,source=null,rafId=null,windowStart=Date.now();
var STREAMS={fip:'fip-hifi.aac',franceinter:'franceinter-hifi.aac',franceculture:'franceculture-hifi.aac',francemusique:'francemusique-hifi.aac',mouv:'mouv-hifi.aac',franceinfo:'franceinfo-hifi.aac'};
var BASE='https://icecast.radiofrance.fr/';
function dlap(e){var s=2/(100*e),p=1-Math.exp(-s);function g(){return Math.max(1,Math.ceil(Math.log(Math.max(Math.random(),1e-10))/Math.log(1-p)));}return(g()-g())*s;}
function play(id){
  document.querySelectorAll('.sb').forEach(function(b){b.classList.remove('active');});
  document.getElementById('b-'+id).classList.add('active');
  var a=document.getElementById('va');
  a.src=BASE+STREAMS[id];
  a.controls=true;
  a.play().catch(function(){});
  document.getElementById('vp').style.display='block';
  windowStart=Date.now();
  if(!audioCtx){
    audioCtx=new(window.AudioContext||window.webkitAudioContext)();
    analyser=audioCtx.createAnalyser();
    analyser.fftSize=256;
    source=audioCtx.createMediaElementSource(a);
    source.connect(analyser);
    analyser.connect(audioCtx.destination);
  }
  if(rafId)cancelAnimationFrame(rafId);
  tick();
}
function tick(){
  var d=new Uint8Array(analyser.frequencyBinCount);
  analyser.getByteFrequencyData(d);
  var s=0;for(var i=0;i<d.length;i++)s+=d[i];
  var raw=s/d.length/255;
  var sig=Math.min(1,Math.max(0,raw+dlap(0.5)));
  document.getElementById('vs').textContent=sig.toFixed(4);
  document.getElementById('vw').textContent=Math.floor((Date.now()-windowStart)/1000)+'s';
  rafId=requestAnimationFrame(tick);
}

const fileInput = document.getElementById('audioFile');
const audio = document.getElementById('audio');
const signal = document.getElementById('signal');
const status = document.getElementById('status');

let ctx;
let analyser;

function updateSignal(v) {
  signal.textContent = v.toFixed(3);
}

fileInput.addEventListener('change', async (e) => {
  const file = e.target.files[0];

  if (!file) return;

  const url = URL.createObjectURL(file);

  audio.src = url;

  if (!ctx) {
    ctx = new AudioContext();

    const src = ctx.createMediaElementSource(audio);

    analyser = ctx.createAnalyser();
    analyser.fftSize = 256;

    src.connect(analyser);
    analyser.connect(ctx.destination);
  }

  await audio.play();

  status.textContent = 'LIVE ANALYSIS';

  const data = new Uint8Array(analyser.frequencyBinCount);

  function tick() {
    if (audio.paused) return;

    analyser.getByteFrequencyData(data);

    let sum = 0;

    for (let i = 0; i < data.length; i++) {
      sum += data[i];
    }

    const vera =
      (sum / data.length) / 255;

    updateSignal(vera);

    requestAnimationFrame(tick);
  }

  tick();
});

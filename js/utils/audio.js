// MailSentry AI — Tactical Cyber SOC Web Audio Engine
// Zero external dependencies — 100% Web Audio API synthesis

window.AudioEngine = (() => {
  let ctx = null;
  let muted = false;

  function getCtx() {
    if (!ctx) ctx = new (window.AudioContext || window.webkitAudioContext)();
    if (ctx.state === 'suspended') ctx.resume();
    return ctx;
  }

  function playTone({ frequency = 440, type = 'sine', duration = 0.12, gain = 0.18, delay = 0 }) {
    if (muted) return;
    const c = getCtx();
    const osc = c.createOscillator();
    const gainNode = c.createGain();
    osc.connect(gainNode);
    gainNode.connect(c.destination);
    osc.type = type;
    osc.frequency.setValueAtTime(frequency, c.currentTime + delay);
    gainNode.gain.setValueAtTime(0, c.currentTime + delay);
    gainNode.gain.linearRampToValueAtTime(gain, c.currentTime + delay + 0.01);
    gainNode.gain.exponentialRampToValueAtTime(0.001, c.currentTime + delay + duration);
    osc.start(c.currentTime + delay);
    osc.stop(c.currentTime + delay + duration);
  }

  function playNoise({ duration = 0.08, gain = 0.08, delay = 0 }) {
    if (muted) return;
    const c = getCtx();
    const bufSize = c.sampleRate * duration;
    const buffer = c.createBuffer(1, bufSize, c.sampleRate);
    const data = buffer.getChannelData(0);
    for (let i = 0; i < bufSize; i++) data[i] = Math.random() * 2 - 1;
    const src = c.createBufferSource();
    const gainNode = c.createGain();
    const filter = c.createBiquadFilter();
    filter.type = 'bandpass';
    filter.frequency.value = 2000;
    src.buffer = buffer;
    src.connect(filter);
    filter.connect(gainNode);
    gainNode.connect(c.destination);
    gainNode.gain.setValueAtTime(gain, c.currentTime + delay);
    gainNode.gain.exponentialRampToValueAtTime(0.001, c.currentTime + delay + duration);
    src.start(c.currentTime + delay);
    src.stop(c.currentTime + delay + duration);
  }

  return {
    setMuted(val) { muted = val; },
    isMuted() { return muted; },

    blip() {
      playTone({ frequency: 880, type: 'sine', duration: 0.07, gain: 0.12 });
    },

    navClick() {
      playTone({ frequency: 660, type: 'triangle', duration: 0.06, gain: 0.1 });
    },

    scanStart() {
      [0, 0.05, 0.1].forEach((d, i) => {
        playTone({ frequency: 440 + i * 220, type: 'sine', duration: 0.12, gain: 0.1, delay: d });
      });
    },

    scanComplete() {
      [0, 0.08, 0.16].forEach((d, i) => {
        playTone({ frequency: 660 + i * 110, type: 'triangle', duration: 0.1, gain: 0.12, delay: d });
      });
      playTone({ frequency: 1320, type: 'sine', duration: 0.2, gain: 0.08, delay: 0.24 });
    },

    criticalAlert() {
      // Harsh klaxon for CRITICAL FRAUD
      [0, 0.15, 0.30, 0.45].forEach((d) => {
        playTone({ frequency: 880, type: 'sawtooth', duration: 0.12, gain: 0.2, delay: d });
        playTone({ frequency: 660, type: 'sawtooth', duration: 0.12, gain: 0.15, delay: d + 0.06 });
      });
    },

    warnAlert() {
      playTone({ frequency: 700, type: 'triangle', duration: 0.15, gain: 0.14 });
      playTone({ frequency: 560, type: 'triangle', duration: 0.15, gain: 0.10, delay: 0.18 });
    },

    safeAlert() {
      playTone({ frequency: 528, type: 'sine', duration: 0.15, gain: 0.12 });
      playTone({ frequency: 660, type: 'sine', duration: 0.15, gain: 0.1, delay: 0.18 });
    },

    blockSealed() {
      playNoise({ duration: 0.04, gain: 0.07 });
      playTone({ frequency: 1046, type: 'sine', duration: 0.25, gain: 0.1, delay: 0.05 });
    },

    radarPing() {
      playTone({ frequency: 1200, type: 'sine', duration: 0.18, gain: 0.08 });
      playTone({ frequency: 600, type: 'sine', duration: 0.12, gain: 0.05, delay: 0.1 });
    },

    buttonClick() {
      playTone({ frequency: 750, type: 'square', duration: 0.04, gain: 0.06 });
    }
  };
})();

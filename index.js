/*  OmniGuard Pro — index.js
    Enhanced Features:
    - Continuous alert sound during threats
    - Improved UI/UX with animations
    - User management system
    - Enhanced security settings
    - Detailed event logging
    - Uptime tracking
    - Snapshot capture
*/

/* ========== DOM Elements ========== */
const video = document.getElementById('video');
const overlay = document.getElementById('overlay');
const alertEl = document.getElementById('alert');
const alertText = document.getElementById('alertText');
const facesCountEl = document.getElementById('facesCount');
const motionValEl = document.getElementById('motionVal');
const modelStatusEl = document.getElementById('modelStatus');
const statusBadge = document.getElementById('statusBadge');
const statusText = document.getElementById('statusText');

const pinDisplay = document.getElementById('pinDisplay');
const keypadEl = document.getElementById('keypad');
const shuffleBtn = document.getElementById('shuffleBtn');
const enterPinBtn = document.getElementById('enterPinBtn');
const clearPinBtn = document.getElementById('clearPinBtn');
const strengthBar = document.getElementById('strengthBar');

const enrollBtn = document.getElementById('enrollBtn');
const authBtn = document.getElementById('authBtn');
const captureEnroll = document.getElementById('captureEnroll');
const userNameInput = document.getElementById('userName');
const usersList = document.getElementById('usersList');
const userCount = document.getElementById('userCount');
const clearEnrollments = document.getElementById('clearEnrollments');

const privacyBtn = document.getElementById('privacyBtn');
const soundBtn = document.getElementById('soundBtn');
const lockBtn = document.getElementById('lockBtn');
const snapshotBtn = document.getElementById('snapshotBtn');

const mirrorToggle = document.getElementById('mirrorMe');
const themeToggle = document.getElementById('themeToggle');
const fullscreenBtn = document.getElementById('fullscreenBtn');
const settingsBtn = document.getElementById('settingsBtn');

const autoLockCheck = document.getElementById('autoLock');
const alertSoundCheck = document.getElementById('alertSound');
const recordEventsCheck = document.getElementById('recordEvents');
const sensitivitySlider = document.getElementById('sensitivity');
const sensitivityValue = document.getElementById('sensitivityValue');

const eventsEl = document.getElementById('events');
const clearLog = document.getElementById('clearLog');
const exportLog = document.getElementById('exportLog');
const eventCount = document.getElementById('eventCount');
const threatCount = document.getElementById('threatCount');
const uptimeEl = document.getElementById('uptime');

const alertAudio = document.getElementById('alertAudio');

/* ========== State Variables ========== */
let canvasCtx, canvas;
let running = true;
let privacyOn = false;
let soundOn = true;
let pinBlocked = true;
let pinInput = "";
let isAlertPlaying = false;
let eventCounter = 0;
let threatCounter = 0;
let startTime = Date.now();

/* ========== face-api / model setup ========== */
let useFaceApi = false;
let faceMatcher = null;
let labeledDescriptors = null;
const MODEL_PATH = './models';
const TINY_OPTIONS = new faceapi.TinyFaceDetectorOptions({ 
  inputSize: 224, 
  scoreThreshold: 0.5 
});

async function tryLoadModels() {
  try {
    modelStatusEl.textContent = 'loading...';
    statusText.textContent = 'Loading AI models...';
    
    await faceapi.nets.tinyFaceDetector.loadFromUri(MODEL_PATH);
    await faceapi.nets.faceRecognitionNet.loadFromUri(MODEL_PATH);
    await faceapi.nets.faceLandmark68Net.loadFromUri(MODEL_PATH);
    
    modelStatusEl.textContent = 'ready';
    useFaceApi = true;
    logEvent('✅ AI models loaded successfully', 'success');
    await loadEnrollments();
  } catch (e) {
    console.warn('Face models not available, using fallback detection.', e);
    modelStatusEl.textContent = 'fallback';
    useFaceApi = false;
    logEvent('⚠️ Using motion fallback (models not found)', 'warn');
  }
}

/* ========== Camera Setup ========== */
async function startCamera() {
  try {
    const stream = await navigator.mediaDevices.getUserMedia({ 
      video: { facingMode: 'user', width: 1280, height: 720 }, 
      audio: false 
    });
    video.srcObject = stream;
    video.onloadedmetadata = () => {
      video.play();
      initOverlay();
      if (useFaceApi) detectFacesLoop();
      else motionLoop();
      logEvent('📹 Camera initialized', 'success');
      statusText.textContent = 'System Active';
    };
  } catch (e) {
    applyAlert('danger', '❌ Camera access denied');
    logEvent('❌ Camera access denied', 'threat');
    statusText.textContent = 'Camera Error';
  }
}

function initOverlay() {
  canvas = overlay;
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  canvasCtx = canvas.getContext('2d');
}

/* ========== Detection Loops ========== */
let stability = { noFace: 0, multiFace: 0, okFace: 0 };
const STABILITY_FRAMES = 8;

async function detectFacesLoop() {
  const displaySize = { width: video.videoWidth, height: video.videoHeight };
  faceapi.matchDimensions(overlay, displaySize);

  setInterval(async () => {
    if (!running) return;
    const detections = await faceapi
      .detectAllFaces(video, TINY_OPTIONS)
      .withFaceLandmarks()
      .withFaceDescriptors();
      
    canvasCtx.clearRect(0, 0, canvas.width, canvas.height);

    const resized = faceapi.resizeResults(detections, displaySize);
    
    // Draw colorful boxes
    resized.forEach((det, i) => {
      const box = det.detection.box;
      canvasCtx.strokeStyle = i === 0 ? '#00ff00' : '#ff0000';
      canvasCtx.lineWidth = 3;
      canvasCtx.strokeRect(box.x, box.y, box.width, box.height);
    });

    handleDetections(resized);
  }, 300);
}

function handleDetections(detections) {
  const count = detections.length;
  facesCountEl.textContent = count;
  
  const sensitivity = parseInt(sensitivitySlider.value);
  const threshold = Math.floor(STABILITY_FRAMES * (11 - sensitivity) / 10);
  
  if (count === 0) {
    stability.noFace++;
    stability.multiFace = 0;
    stability.okFace = 0;
    if (stability.noFace >= threshold) {
      setBlocked(true, '🚫 No face detected — Unauthorized access attempt');
      statusText.textContent = 'No Face Detected';
    }
  } else if (count > 1) {
    stability.multiFace++;
    stability.noFace = 0;
    stability.okFace = 0;
    if (stability.multiFace >= threshold) {
      setBlocked(true, `⚠️ ${count} faces detected — Possible shoulder surfing!`);
      statusText.textContent = 'Multiple Faces!';
    }
  } else {
    stability.okFace++;
    stability.noFace = 0;
    stability.multiFace = 0;
    if (stability.okFace >= threshold) {
      setBlocked(false, '✅ Safe: Single authorized user detected');
      statusText.textContent = 'Secure Mode';
    }
    
    // Face recognition
    if (faceMatcher && detections[0].descriptor) {
      const best = faceMatcher.findBestMatch(detections[0].descriptor);
      if (best && best.label !== 'unknown' && best.distance < 0.6) {
        logEvent(`👤 Recognized: ${best.label} (confidence: ${(100 - best.distance * 100).toFixed(1)}%)`, 'success');
        statusText.textContent = `Welcome, ${best.label}`;
      }
    }
  }
}

/* ========== Fallback Motion Detection ========== */
let lastFrame = null;

function motionLoop() {
  const tmpCanvas = document.createElement('canvas');
  const tctx = tmpCanvas.getContext('2d');
  tmpCanvas.width = video.videoWidth;
  tmpCanvas.height = video.videoHeight;

  setInterval(() => {
    if (!running) return;
    tctx.drawImage(video, 0, 0, tmpCanvas.width, tmpCanvas.height);
    const frame = tctx.getImageData(0, 0, tmpCanvas.width, tmpCanvas.height);
    
    if (!lastFrame) {
      lastFrame = frame;
      motionValEl.textContent = '0';
      return;
    }

    let diff = 0;
    for (let i = 0; i < frame.data.length; i += 4) {
      const dr = Math.abs(frame.data[i] - lastFrame.data[i]);
      const dg = Math.abs(frame.data[i + 1] - lastFrame.data[i + 1]);
      const db = Math.abs(frame.data[i + 2] - lastFrame.data[i + 2]);
      diff += (dr + dg + db) / 3;
    }
    diff = diff / (frame.data.length / 4);
    motionValEl.textContent = Math.round(diff);
    lastFrame = frame;

    const sensitivity = parseInt(sensitivitySlider.value);
    const lowThreshold = 8 + (10 - sensitivity);
    const highThreshold = 12 + (sensitivity - 5);

    if (diff < lowThreshold) {
      stability.okFace++;
      if (stability.okFace >= STABILITY_FRAMES) {
        setBlocked(false, '✅ Low motion detected — System secure');
        statusText.textContent = 'Secure Mode';
      }
    } else if (diff > highThreshold) {
      stability.multiFace++;
      if (stability.multiFace >= STABILITY_FRAMES) {
        setBlocked(true, '⚠️ High motion detected — Suspicious activity!');
        statusText.textContent = 'High Motion Alert';
      }
    }
  }, 350);
}

/* ========== Alert Sound Management ========== */
function playAlertSound() {
  if (!alertSoundCheck.checked || !soundOn) return;
  
  if (!isAlertPlaying) {
    isAlertPlaying = true;
    alertAudio.play().catch(e => console.warn('Audio play failed:', e));
  }
}

function stopAlertSound() {
  if (isAlertPlaying) {
    isAlertPlaying = false;
    alertAudio.pause();
    alertAudio.currentTime = 0;
  }
}

/* ========== UI Helper Functions ========== */
function setBlocked(state, message) {
  const autoLock = autoLockCheck.checked;
  
  if (state && autoLock) {
    pinBlocked = true;
    pinDisplay.placeholder = 'PIN BLOCKED';
    pinDisplay.disabled = true;
    pinDisplay.classList.add('disabled');
    applyAlert('danger', message);
    playAlertSound();
    logEvent(message, 'threat');
  } else if (!state) {
    pinBlocked = false;
    pinDisplay.placeholder = 'Enter PIN';
    pinDisplay.disabled = false;
    pinDisplay.classList.remove('disabled');
    applyAlert('safe', message);
    stopAlertSound();
  }
}

function applyAlert(type, text) {
  const icons = {
    safe: '✅',
    warn: '⚠️',
    danger: '🚨',
    neutral: '🔍'
  };
  
  alertEl.className = 'alert ' + type;
  alertText.textContent = text;
  document.querySelector('.alert-icon').textContent = icons[type] || '🔍';
  
  // Animate alert
  alertEl.style.animation = 'none';
  setTimeout(() => {
    alertEl.style.animation = type === 'danger' ? 'shake 0.5s' : '';
  }, 10);
}

function playBeep() {
  if (!soundOn) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o = ctx.createOscillator();
    const g = ctx.createGain();
    o.type = 'sine';
    o.frequency.value = 1200;
    g.gain.value = 0.15;
    o.connect(g);
    g.connect(ctx.destination);
    o.start();
    setTimeout(() => {
      o.stop();
      ctx.close();
    }, 150);
  } catch (e) {
    console.warn('Audio not available', e);
  }
}

/* ========== Virtual Keypad ========== */
function buildKeypad() {
  keypadEl.innerHTML = '';
  let digits = ['1', '2', '3', '4', '5', '6', '7', '8', '9', '0', 'X'];
  digits = shuffleArray(digits);
  
  for (const d of digits) {
    const btn = document.createElement('button');
    btn.textContent = d;
    btn.onclick = () => pressKey(d);
    keypadEl.appendChild(btn);
  }
}

function shuffleArray(a) {
  return a.sort(() => Math.random() - 0.5);
}

function pressKey(d) {
  if (pinBlocked) {
    toast('🚫 PIN blocked — Unsafe to enter', 'danger');
    playBeep();
    return;
  }
  
  if (d === 'X') {
    pinInput = pinInput.slice(0, -1);
  } else if (pinInput.length < 8) {
    pinInput += d;
    playBeep();
  }
  
  pinDisplay.value = '●'.repeat(pinInput.length);
  updatePinStrength();
}

function updatePinStrength() {
  const strength = (pinInput.length / 8) * 100;
  strengthBar.style.width = strength + '%';
}

enterPinBtn.onclick = () => {
  if (pinBlocked) {
    toast('🚫 PIN blocked — Cannot submit', 'danger');
    return;
  }
  
  if (pinInput.length < 4) {
    toast('⚠️ PIN too short (min 4 digits)', 'warn');
    return;
  }
  
  // Demo PIN: 1234
  if (pinInput === '1234') {
    toast('✅ PIN correct — Access granted!', 'success');
    logEvent('✅ PIN authentication successful', 'success');
    playSuccessSound();
  } else {
    toast('❌ Incorrect PIN', 'danger');
    logEvent('❌ Failed PIN attempt', 'threat');
    playBeep();
  }
  
  pinInput = '';
  pinDisplay.value = '';
  updatePinStrength();
  buildKeypad();
};

clearPinBtn.onclick = () => {
  pinInput = '';
  pinDisplay.value = '';
  updatePinStrength();
};

shuffleBtn.onclick = () => {
  buildKeypad();
  toast('🔀 Keypad shuffled', 'neutral');
};

function playSuccessSound() {
  if (!soundOn) return;
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const o1 = ctx.createOscillator();
    const o2 = ctx.createOscillator();
    const g = ctx.createGain();
    
    o1.type = 'sine';
    o2.type = 'sine';
    o1.frequency.value = 523.25; // C5
    o2.frequency.value = 659.25; // E5
    g.gain.value = 0.1;
    
    o1.connect(g);
    o2.connect(g);
    g.connect(ctx.destination);
    
    o1.start();
    o2.start();
    
    setTimeout(() => {
      o1.stop();
      o2.stop();
      ctx.close();
    }, 200);
  } catch (e) {
    console.warn('Audio error', e);
  }
}

/* ========== Face Enrollment & Auth ========== */
function saveLabeledDescriptors() {
  if (!labeledDescriptors) return;
  const store = labeledDescriptors.map(ld => ({
    label: ld.label,
    descriptors: ld.descriptors.map(d => Array.from(d))
  }));
  localStorage.setItem('omni_labeled', JSON.stringify(store));
  updateUsersList();
}

async function loadEnrollments() {
  const raw = localStorage.getItem('omni_labeled');
  if (!raw) {
    labeledDescriptors = null;
    faceMatcher = null;
    updateUsersList();
    return;
  }
  
  try {
    const parsed = JSON.parse(raw);
    labeledDescriptors = parsed.map(p => new faceapi.LabeledFaceDescriptors(
      p.label,
      p.descriptors.map(d => new Float32Array(d))
    ));
    faceMatcher = new faceapi.FaceMatcher(labeledDescriptors, 0.6);
    logEvent(`📂 Loaded ${parsed.length} enrolled user(s)`, 'success');
    updateUsersList();
  } catch (e) {
    console.warn('Failed to load enrollments', e);
    logEvent('⚠️ Failed to load enrollments', 'warn');
  }
}

function updateUsersList() {
  const raw = localStorage.getItem('omni_labeled');
  if (!raw) {
    usersList.innerHTML = '<div style="text-align:center;color:var(--muted);padding:20px;">No enrolled users</div>';
    userCount.textContent = '0';
    return;
  }
  
  try {
    const parsed = JSON.parse(raw);
    userCount.textContent = parsed.length;
    
    usersList.innerHTML = '';
    parsed.forEach((user, index) => {
      const item = document.createElement('div');
      item.className = 'user-item';
      item.innerHTML = `
        <div class="user-info">
          <div class="user-avatar">${user.label.charAt(0).toUpperCase()}</div>
          <div class="user-name">${user.label}</div>
        </div>
        <button class="user-delete" onclick="deleteUser(${index})">🗑️</button>
      `;
      usersList.appendChild(item);
    });
  } catch (e) {
    console.warn('Error updating users list', e);
  }
}

window.deleteUser = function(index) {
  const raw = localStorage.getItem('omni_labeled');
  if (!raw) return;
  
  try {
    const parsed = JSON.parse(raw);
    const userName = parsed[index].label;
    parsed.splice(index, 1);
    localStorage.setItem('omni_labeled', JSON.stringify(parsed));
    loadEnrollments();
    toast(`🗑️ Deleted user: ${userName}`, 'warn');
    logEvent(`🗑️ User deleted: ${userName}`, 'warn');
  } catch (e) {
    console.warn('Error deleting user', e);
  }
};

enrollBtn.onclick = () => {
  toast('📸 Ready to enroll — Enter name and click Capture', 'neutral');
  userNameInput.focus();
};

captureEnroll.onclick = async () => {
  const name = (userNameInput.value || '').trim();
  if (!name) {
    toast('⚠️ Name required for enrollment', 'warn');
    return;
  }
  
  if (!useFaceApi) {
    toast('❌ Face models unavailable — Cannot enroll', 'danger');
    return;
  }
  
  const det = await faceapi
    .detectSingleFace(video, TINY_OPTIONS)
    .withFaceLandmarks()
    .withFaceDescriptor();
    
  if (!det) {
    toast('❌ No clear face detected — Try again', 'danger');
    return;
  }
  
  const existing = JSON.parse(localStorage.getItem('omni_labeled') || '[]');
  existing.push({ 
    label: name, 
    descriptors: [Array.from(det.descriptor)] 
  });
  localStorage.setItem('omni_labeled', JSON.stringify(existing));
  
  await loadEnrollments();
  toast(`✅ Successfully enrolled: ${name}`, 'success');
  userNameInput.value = '';
  logEvent(`✅ New user enrolled: ${name}`, 'success');
  playSuccessSound();
};

authBtn.onclick = async () => {
  if (!useFaceApi) {
    toast('❌ Face models unavailable', 'danger');
    return;
  }
  
  const det = await faceapi
    .detectSingleFace(video, TINY_OPTIONS)
    .withFaceLandmarks()
    .withFaceDescriptor();
    
  if (!det) {
    toast('❌ No face detected for authentication', 'danger');
    return;
  }
  
  if (!faceMatcher) {
    toast('⚠️ No enrolled users in system', 'warn');
    return;
  }
  
  const best = faceMatcher.findBestMatch(det.descriptor);
  
  if (best.label === 'unknown') {
    toast('❌ User not recognized', 'danger');
    logEvent('❌ Authentication failed (unknown user)', 'threat');
    playBeep();
  } else {
    toast(`✅ Welcome back, ${best.label}!`, 'success');
    logEvent(`✅ Authentication successful: ${best.label}`, 'success');
    playSuccessSound();
  }
};

clearEnrollments.onclick = () => {
  if (!confirm('⚠️ Delete all enrolled users? This cannot be undone!')) {
    return;
  }
  
  localStorage.removeItem('omni_labeled');
  labeledDescriptors = null;
  faceMatcher = null;
  updateUsersList();
  toast('🗑️ All enrollments cleared', 'warn');
  logEvent('🗑️ All user enrollments cleared', 'warn');
};

/* ========== Privacy & Control Features ========== */
privacyBtn.onclick = () => {
  privacyOn = !privacyOn;
  
  if (privacyOn) {
    video.style.filter = 'blur(12px) saturate(0.6)';
    pinDisplay.style.filter = 'blur(8px)';
    privacyBtn.classList.add('active');
    toast('🔒 Privacy blur ENABLED', 'warn');
    logEvent('🔒 Privacy mode activated');
  } else {
    video.style.filter = 'none';
    pinDisplay.style.filter = 'none';
    privacyBtn.classList.remove('active');
    toast('🔓 Privacy blur DISABLED', 'neutral');
    logEvent('🔓 Privacy mode deactivated');
  }
};

soundBtn.onclick = () => {
  soundOn = !soundOn;
  soundBtn.classList.toggle('active');
  
  if (!soundOn) {
    stopAlertSound();
  }
  
  toast(`🔊 Sound ${soundOn ? 'ENABLED' : 'DISABLED'}`, 'neutral');
  logEvent(`🔊 Sound ${soundOn ? 'enabled' : 'disabled'}`);
};

lockBtn.onclick = () => {
  setBlocked(true, '🔐 EMERGENCY LOCK ACTIVATED!');
  toast('🔐 System manually locked', 'danger');
  logEvent('🔐 Emergency lock activated by user', 'threat');
  
  // Force reset stability
  stability = { noFace: STABILITY_FRAMES, multiFace: 0, okFace: 0 };
};

snapshotBtn.onclick = () => {
  const snapshotCanvas = document.createElement('canvas');
  const ctx = snapshotCanvas.getContext('2d');
  snapshotCanvas.width = video.videoWidth;
  snapshotCanvas.height = video.videoHeight;
  
  ctx.drawImage(video, 0, 0);
  
  snapshotCanvas.toBlob(blob => {
    if (!blob) {
      toast('❌ Snapshot failed — camera not ready', 'danger');
      logEvent('❌ Snapshot failed (empty blob)', 'warn');
      return;
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    a.href = url;
    a.download = `omniguard-snapshot-${timestamp}.png`;
    a.click();
    URL.revokeObjectURL(url);
    
    toast('📷 Snapshot saved', 'success');
    logEvent('📷 Security snapshot captured', 'success');
  });
};

/* ========== Mirror & Theme Controls ========== */
mirrorToggle.onchange = () => {
  video.style.transform = mirrorToggle.checked ? 'scaleX(-1)' : 'scaleX(1)';
  toast(`🪞 Mirror ${mirrorToggle.checked ? 'ON' : 'OFF'}`, 'neutral');
};

themeToggle.onclick = () => {
  document.body.classList.toggle('light');
  const isLight = document.body.classList.contains('light');
  toast(`${isLight ? '☀️' : '🌙'} ${isLight ? 'Light' : 'Dark'} theme activated`, 'neutral');
  logEvent(`Theme changed to ${isLight ? 'light' : 'dark'} mode`);
};

fullscreenBtn.onclick = () => {
  if (!document.fullscreenElement) {
    document.documentElement.requestFullscreen().then(() => {
      toast('⛶ Fullscreen mode enabled', 'neutral');
    }).catch(e => {
      toast('❌ Fullscreen not supported', 'danger');
    });
  } else {
    document.exitFullscreen();
    toast('⛶ Fullscreen mode disabled', 'neutral');
  }
};

settingsBtn.onclick = () => {
  toast('⚙️ Settings panel available below', 'neutral');
  document.querySelector('.settings-card').scrollIntoView({ behavior: 'smooth' });
};

/* ========== Settings Controls ========== */
sensitivitySlider.oninput = () => {
  sensitivityValue.textContent = sensitivitySlider.value;
};

sensitivitySlider.onchange = () => {
  logEvent(`⚙️ Sensitivity adjusted to ${sensitivitySlider.value}`, 'neutral');
};

/* ========== Event Logging ========== */
function logEvent(text, type = 'neutral') {
  if (!recordEventsCheck.checked) return;
  
  eventCounter++;
  if (type === 'threat' || type === 'danger') {
    threatCounter++;
  }
  
  const time = new Date().toLocaleTimeString();
  const div = document.createElement('div');
  div.className = `event ${type}`;
  div.innerHTML = `
    <span class="event-time">${time}</span>
    <span class="event-text">${text}</span>
  `;
  
  eventsEl.prepend(div);
  
  // Update counters
  eventCount.textContent = eventCounter;
  threatCount.textContent = threatCounter;
  
  // Keep max 100 events
  while (eventsEl.children.length > 100) {
    eventsEl.removeChild(eventsEl.lastChild);
  }
  
  // Save to localStorage
  saveEventLog();
}

function saveEventLog() {
  const events = Array.from(eventsEl.children).map(e => e.textContent).slice(0, 50);
  localStorage.setItem('omni_events', JSON.stringify(events));
}

function loadEventLog() {
  const saved = localStorage.getItem('omni_events');
  if (!saved) return;
  
  try {
    const events = JSON.parse(saved);
    events.forEach(text => {
      const div = document.createElement('div');
      div.className = 'event';
      div.textContent = text;
      eventsEl.appendChild(div);
      eventCounter++;
    });
  } catch (e) {
    console.warn('Failed to load event log', e);
  }
}

clearLog.onclick = () => {
  if (!confirm('Clear all security logs?')) return;
  
  eventsEl.innerHTML = '';
  eventCounter = 0;
  threatCounter = 0;
  eventCount.textContent = '0';
  threatCount.textContent = '0';
  localStorage.removeItem('omni_events');
  toast('🗑️ Event log cleared', 'neutral');
};

exportLog.onclick = () => {
  const events = Array.from(eventsEl.children).map(e => e.textContent).join('\n');
  const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
  const content = `OmniGuard Pro - Security Event Log
Generated: ${new Date().toLocaleString()}
Total Events: ${eventCounter}
Threat Events: ${threatCounter}
${'='.repeat(60)}

${events}
`;
  
  const blob = new Blob([content], { type: 'text/plain' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `omniguard-log-${timestamp}.txt`;
  a.click();
  URL.revokeObjectURL(url);
  
  toast('💾 Event log exported', 'success');
  logEvent('💾 Security log exported to file', 'success');
};

/* ========== Toast Notifications ========== */
function toast(text, type = 'neutral') {
  const icons = {
    success: '✅',
    danger: '❌',
    warn: '⚠️',
    neutral: 'ℹ️'
  };
  
  const toastDiv = document.createElement('div');
  toastDiv.className = `alert ${type}`;
  toastDiv.style.cssText = `
    position: fixed;
    top: 90px;
    right: 24px;
    z-index: 1000;
    max-width: 400px;
    animation: slideInRight 0.3s ease-out;
  `;
  toastDiv.innerHTML = `
    <span class="alert-icon">${icons[type]}</span>
    <span>${text}</span>
  `;
  
  document.body.appendChild(toastDiv);
  
  setTimeout(() => {
    toastDiv.style.animation = 'fadeOut 0.3s ease-out';
    setTimeout(() => toastDiv.remove(), 300);
  }, 3000);
}

// Add CSS for toast animations
const style = document.createElement('style');
style.textContent = `
  @keyframes slideInRight {
    from { transform: translateX(100%); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
  }
  @keyframes fadeOut {
    from { opacity: 1; }
    to { opacity: 0; }
  }
`;
document.head.appendChild(style);

/* ========== Uptime Counter ========== */
function updateUptime() {
  const elapsed = Date.now() - startTime;
  const minutes = Math.floor(elapsed / 60000);
  const seconds = Math.floor((elapsed % 60000) / 1000);
  uptimeEl.textContent = `${String(minutes).padStart(2, '0')}:${String(seconds).padStart(2, '0')}`;
}

setInterval(updateUptime, 1000);

/* ========== Keyboard Shortcuts ========== */
document.addEventListener('keydown', (e) => {
  // Ctrl/Cmd + L: Lock
  if ((e.ctrlKey || e.metaKey) && e.key === 'l') {
    e.preventDefault();
    lockBtn.click();
  }
  
  // Ctrl/Cmd + P: Privacy
  if ((e.ctrlKey || e.metaKey) && e.key === 'p') {
    e.preventDefault();
    privacyBtn.click();
  }
  
  // Ctrl/Cmd + S: Snapshot
  if ((e.ctrlKey || e.metaKey) && e.key === 's') {
    e.preventDefault();
    snapshotBtn.click();
  }
  
  // Escape: Exit fullscreen
  if (e.key === 'Escape' && document.fullscreenElement) {
    document.exitFullscreen();
  }
});

/* ========== Auto-save Settings ========== */
function saveSettings() {
  const settings = {
    autoLock: autoLockCheck.checked,
    alertSound: alertSoundCheck.checked,
    recordEvents: recordEventsCheck.checked,
    sensitivity: sensitivitySlider.value,
    soundOn: soundOn,
    theme: document.body.classList.contains('light') ? 'light' : 'dark'
  };
  localStorage.setItem('omni_settings', JSON.stringify(settings));
}

function loadSettings() {
  const saved = localStorage.getItem('omni_settings');
  if (!saved) return;
  
  try {
    const settings = JSON.parse(saved);
    autoLockCheck.checked = settings.autoLock ?? true;
    alertSoundCheck.checked = settings.alertSound ?? true;
    recordEventsCheck.checked = settings.recordEvents ?? true;
    sensitivitySlider.value = settings.sensitivity ?? 5;
    sensitivityValue.textContent = sensitivitySlider.value;
    soundOn = settings.soundOn ?? true;
    
    if (settings.theme === 'light') {
      document.body.classList.add('light');
    }
    
    soundBtn.classList.toggle('active', soundOn);
  } catch (e) {
    console.warn('Failed to load settings', e);
  }
}

// Save settings on change
[autoLockCheck, alertSoundCheck, recordEventsCheck].forEach(el => {
  el.addEventListener('change', saveSettings);
});
sensitivitySlider.addEventListener('change', saveSettings);

/* ========== Initialization ========== */
(async function init() {
  logEvent('🚀 OmniGuard Pro initializing...', 'neutral');
  
  // Load saved data
  loadSettings();
  loadEventLog();
  
  // Build initial keypad
  buildKeypad();
  
  // Load AI models
  await tryLoadModels();
  
  // Start camera
  await startCamera();
  
  // Initial state
  setBlocked(true, '🔍 Running security checks...');
  
  // Update users list
  updateUsersList();
  
  logEvent('✅ OmniGuard Pro started successfully', 'success');
  
  // Welcome message
  setTimeout(() => {
    toast('🛡️ OmniGuard Pro is protecting your privacy', 'success');
  }, 1000);
})();

/* ========== Cleanup on page unload ========== */
window.addEventListener('beforeunload', () => {
  stopAlertSound();
  saveSettings();
  saveEventLog();
  
  if (video.srcObject) {
    video.srcObject.getTracks().forEach(track => track.stop());
  }
});
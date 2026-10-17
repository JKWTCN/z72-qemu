// SPDX-License-Identifier: GPL-2.0-or-later
'use strict';
const $ = id => document.getElementById(id);
const held = new Set();
let available = false, running = false, restarting = false, queue = Promise.resolve();
let frameBusy = false, lastUrl = null, seenFrame = false;
const names = ['待机', '菜单', '播放', '拍摄', '提示'];

function notice(text, error = false) {
  $('notice').textContent = text;
  $('notice').classList.toggle('error', error);
}

async function request(path, body) {
  const response = await fetch(path, {
    method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify(body), keepalive: true, signal: AbortSignal.timeout(10000)
  });
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || '操作失败');
  return result;
}

// Input requests share one queue so a quick release cannot overtake a press.
function send(path, body = {}) {
  queue = queue.then(() => request(path, body)).catch(error => notice(error.message, true));
  return queue;
}

function paintKeys() {
  document.querySelectorAll('[data-pin]').forEach(button => {
    const down = held.has(Number(button.dataset.pin));
    button.classList.toggle('held', down);
    button.setAttribute('aria-pressed', String(down));
  });
}

function press(pin, down) {
  if (down && !available) return;
  if (held.has(pin) === down) return;
  if (down) held.add(pin); else held.delete(pin);
  paintKeys();
  send('/key', {pin, level: down ? 0 : 1});
}

function releaseAll() {
  held.clear();
  paintKeys();
  return send('/release');
}

// Names recovered from the firmware input tables; blank entries are unknown.
const pinNames = {0: '退出菜单·实测', 1: '释放模式', 2: 'I 键', 3: 'OK', 4: '下',
  5: '上', 6: '左', 7: '右', 8: '播放', 9: '菜单', 10: '显示', 20: 'ISO',
  22: '缩略图', 23: '变焦'};
for (let pin = 0; pin < 24; pin++) {
  const button = document.createElement('button');
  button.className = 'key';
  button.dataset.pin = pin;
  const name = pinNames[pin];
  button.textContent = name || String(pin).padStart(2, '0');
  button.title = name ? `输入 ${pin} · ${name}` : `输入 ${pin}`;
  button.setAttribute('aria-label', `扩展按键 ${pin}`);
  button.disabled = true;
  $('extra-keys').appendChild(button);
}
document.querySelectorAll('[data-pin]').forEach(button => {
  const pin = Number(button.dataset.pin);
  button.setAttribute('aria-pressed', 'false');
  button.addEventListener('pointerdown', event => {
    if (event.button !== 0) return;
    event.preventDefault();
    button.setPointerCapture(event.pointerId);
    press(pin, true);
  });
  for (const type of ['pointerup', 'pointercancel', 'lostpointercapture']) {
    button.addEventListener(type, () => press(pin, false));
  }
  button.addEventListener('contextmenu', event => event.preventDefault());
  button.addEventListener('keydown', event => {
    if (event.key === ' ' || event.key === 'Enter') {
      event.preventDefault();
      if (!event.repeat) press(pin, true);
    }
  });
  button.addEventListener('keyup', event => {
    if (event.key === ' ' || event.key === 'Enter') {
      event.preventDefault();
      press(pin, false);
    }
  });
  button.addEventListener('blur', () => press(pin, false));
});

// Firmware-confirmed inputs: 3 OK, 8 playback, 9 menu, 4/5/6/7 pad directions.
const shortcuts = {KeyM: 9, KeyP: 8, Enter: 3, ArrowUp: 5, ArrowDown: 4, ArrowLeft: 6, ArrowRight: 7};
function shortcut(event, down) {
  if (event.ctrlKey || event.metaKey || event.altKey) return;
  if (event.code === 'Escape' && down) { if (!event.repeat) releaseAll(); return; }
  if (event.code === 'Enter' && event.target.closest('button,summary')) return;
  const pin = shortcuts[event.code];
  if (pin !== undefined) {
    event.preventDefault();
    if (!event.repeat) press(pin, down);
  }
}
document.addEventListener('keydown', event => shortcut(event, true));
document.addEventListener('keyup', event => shortcut(event, false));
window.addEventListener('blur', releaseAll);
window.addEventListener('pagehide', releaseAll);
document.addEventListener('visibilitychange', () => { if (document.hidden) releaseAll(); });
$('release').onclick = releaseAll;
$('auto-menu').onchange = () => {
  send('/auto-menu', {enabled: $('auto-menu').checked});
  if ($('auto-menu').checked) notice('将在启动窗口内自动按下菜单键。');
  else notice('已关闭自动按下菜单，需在拍摄画面刚出现时手动点击 MENU。');
};
$('restart').onclick = async () => {
  if (restarting) return;
  restarting = true;
  available = running = false;
  held.clear(); paintKeys();
  await send('/restart');
  if (lastUrl) URL.revokeObjectURL(lastUrl);
  lastUrl = null; seenFrame = false;
  $('frame').hidden = true;
  $('placeholder').hidden = false;
  $('frame-state').textContent = '等待首帧';
  notice('正在重新启动，请稍候…');
  await status();
};

setInterval(() => { if (held.size) send('/heartbeat'); }, 1000);

async function frame() {
  if (frameBusy || !running || !$('live').checked || document.hidden) return;
  frameBusy = true;
  try {
    const response = await fetch('/frame', {signal: AbortSignal.timeout(10000)});
    if (!response.ok) throw new Error('画面暂不可用');
    const blob = await response.blob();
    if (!running) return;
    const url = URL.createObjectURL(blob);
    $('frame').src = url;
    if (lastUrl) URL.revokeObjectURL(lastUrl);
    lastUrl = url;
    $('frame').hidden = false;
    $('placeholder').hidden = true;
    seenFrame = true;
    $('frame-state').textContent = '实时 · 720 × 480';
  } catch (error) {
    $('frame-state').textContent = error.message;
  } finally { frameBusy = false; }
}
$('live').onchange = () => {
  if ($('live').checked) frame();
  else $('frame-state').textContent = '画面刷新已暂停';
};

let statusBusy = false;
async function status() {
  if (statusBusy) return;
  statusBusy = true;
  try {
    const response = await fetch('/status', {signal: AbortSignal.timeout(10000)});
    const state = await response.json();
    if (!response.ok) throw new Error(state.error || '读取状态失败');
    running = state.phase === 'running' && state.execution === 'running';
    available = running && state.input_ready === true;
    restarting = state.phase === 'starting';
    $('auto-menu').checked = state.auto_menu !== 'off';
    $('auto-menu').disabled = restarting;
    $('connection').textContent = ({starting: '启动中', running: running ? (available ? '运行中' : '初始化中') : '已暂停',
      failed: '启动失败', stopped: '已停止'})[state.phase] || '连接中';
    $('connection').className = `pill ${state.phase}`;
    document.querySelectorAll('[data-pin]').forEach(button => { button.disabled = !available; });
    $('release').disabled = !available;
    $('restart').disabled = restarting;
    $('application').textContent = '前台应用 · ' + (state.ready ? (names[state.index] || '切换中') : '初始化中');
    const seconds = state.uptime || 0;
    $('uptime').textContent = `${String(Math.floor(seconds / 60)).padStart(2, '0')}:${String(seconds % 60).padStart(2, '0')}`;
    if (state.error) notice(state.error, true);
    else if (restarting) notice('正在启动模拟器，冷启动可能需要几分钟…');
    else if (available && state.index === 1) notice('菜单应用已打开。可继续操作，画面响应以当前固件为准。');
    else if (available && state.menu_inhibited === true) notice('固件当前状态阻止打开菜单，可重启模拟器重试。', true);
    else if (available) notice('连接就绪。方向键移动高亮；MENU 仅在拍摄画面刚出现的一小段窗口内有效。');
    else if (running && state.auto_menu === 'armed') notice('正在启动，将在拍摄画面出现的窗口内自动按下菜单键…');
    else if (running) notice('固件正在初始化显示与输入，请稍候…');
    else notice('模拟器尚未运行，可点击重启。');
    if (running && !seenFrame) frame();
  } catch (error) {
    available = running = false;
    $('connection').textContent = '连接断开';
    $('connection').className = 'pill failed';
    document.querySelectorAll('[data-pin]').forEach(button => { button.disabled = true; });
    notice(`连接失败：${error.message}。正在重试…`, true);
    held.clear(); paintKeys();
  } finally { statusBusy = false; }
}
// Schedule from completion so a slow capture cannot accumulate requests.
async function refreshFrames() {
  const started = performance.now();
  await frame();
  setTimeout(refreshFrames, Math.max(1, 1000 / 30 - (performance.now() - started)));
}
refreshFrames();
setInterval(status, 1500);
status();

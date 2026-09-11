(() => {
  'use strict';

  const videoDirectory = new URL(document.body.dataset.videoDirectory || 'assets/videos/', document.baseURI);
  const fullVideoUrl = new URL(document.body.dataset.videoFile || 'yuanxingmu-webui.mp4', videoDirectory);
  const chapterDataUrl = new URL('chapters.json', videoDirectory);
  const player = document.getElementById('demo-player');
  const placeholder = document.getElementById('film-placeholder');
  const placeholderTitle = document.getElementById('placeholder-title');
  const placeholderDetail = document.getElementById('placeholder-detail');
  const filmStatus = document.getElementById('film-status');
  const playerNote = document.getElementById('player-note');
  const downloadFull = document.getElementById('download-full');
  const retryButton = document.getElementById('retry-media');
  const chapterList = document.getElementById('chapter-list');
  const chaptersPending = document.getElementById('chapters-pending');
  const chaptersPendingTitle = document.getElementById('chapters-pending-title');
  const chaptersPendingDetail = document.getElementById('chapters-pending-detail');
  const chapterFeedback = document.getElementById('chapter-feedback');
  let fullVideoReady = false;
  let refreshInProgress = false;
  let chapterItems = [];

  function formatTime(seconds) {
    const value = Math.max(0, Math.floor(seconds));
    const hours = Math.floor(value / 3600);
    const minutes = Math.floor((value % 3600) / 60);
    const rest = value % 60;
    return hours
      ? `${hours}:${String(minutes).padStart(2, '0')}:${String(rest).padStart(2, '0')}`
      : `${String(minutes).padStart(2, '0')}:${String(rest).padStart(2, '0')}`;
  }

  async function fetchWithTimeout(url, options = {}) {
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 10000);
    try {
      return await fetch(url, { cache: 'no-store', ...options, signal: controller.signal });
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function checkVideo(url) {
    try {
      const response = await fetchWithTimeout(url, { method: 'HEAD' });
      if (response.status === 404 || response.status === 410) return 'missing';
      if (response.status === 405 || response.status === 501) return 'unconfirmed';
      if (!response.ok) return 'unavailable';
      const type = response.headers.get('content-type') || '';
      return type.includes('text/html') ? 'unavailable' : 'available';
    } catch {
      return 'unavailable';
    }
  }

  function updateChapterButtons() {
    for (const item of chapterItems) {
      item.button.disabled = !fullVideoReady;
      item.button.setAttribute('aria-label', fullVideoReady
        ? `从 ${formatTime(item.start)} 观看：${item.title}`
        : `${item.title}，完整视频暂不可观看`);
    }
  }

  function setVideoUnavailable(missing) {
    fullVideoReady = false;
    player.hidden = true;
    placeholder.hidden = false;
    downloadFull.hidden = true;
    filmStatus.classList.add('is-pending');
    filmStatus.textContent = missing ? '待录制' : '暂不可播放';
    placeholderTitle.textContent = missing ? '演示视频待录制' : '视频暂时无法播放';
    placeholderDetail.textContent = missing
      ? '录制完成后，可在这里观看完整过程或按章节观看。'
      : '请稍后刷新查看；已发布的片段也可在下方单独观看。';
    playerNote.textContent = missing
      ? '视频发布后，可播放、拖动进度或全屏观看。'
      : '请稍后再试，也可以先查看下方已发布的片段。';
    updateChapterButtons();
  }

  async function loadFullVideo() {
    const availability = await checkVideo(fullVideoUrl);
    if (availability === 'missing' || availability === 'unavailable') {
      setVideoUnavailable(availability === 'missing');
      return;
    }
    filmStatus.textContent = '正在加载';
    placeholderTitle.textContent = '正在加载演示视频';
    placeholderDetail.textContent = '加载完成后，点击播放开始观看。';
    await new Promise((resolve) => {
      const timer = window.setTimeout(() => finish(false), 20000);
      const finish = (ready) => {
        window.clearTimeout(timer);
        player.removeEventListener('loadedmetadata', onReady);
        player.removeEventListener('error', onError);
        if (ready && Number.isFinite(player.duration) && player.duration > 0) {
          fullVideoReady = true;
          player.hidden = false;
          placeholder.hidden = true;
          downloadFull.hidden = false;
          filmStatus.classList.remove('is-pending');
          filmStatus.textContent = '可观看';
          playerNote.textContent = `完整演示 · ${formatTime(player.duration)} · 点击播放开始观看`;
          updateChapterButtons();
        } else {
          setVideoUnavailable(false);
        }
        resolve();
      };
      const onReady = () => finish(true);
      const onError = () => finish(false);
      player.addEventListener('loadedmetadata', onReady, { once: true });
      player.addEventListener('error', onError, { once: true });
      player.src = fullVideoUrl.href;
      player.load();
    });
  }

  function showChapterPending(missing) {
    chapterItems = [];
    chapterList.replaceChildren();
    chapterList.hidden = true;
    chaptersPending.hidden = false;
    chaptersPendingTitle.textContent = missing ? '章节待录制' : '章节暂时无法加载';
    chaptersPendingDetail.textContent = missing
      ? '录制完成后，这里将显示实际视频的章节。'
      : '可先观看已发布的完整视频，稍后再刷新章节。';
  }

  function parseChapters(data) {
    if (!data || !Array.isArray(data.chapters)) throw new Error('Invalid chapter list');
    const seenSteps = new Set();
    return data.chapters.map((chapter) => {
      if (!chapter || typeof chapter.step !== 'string' || !/^[a-z0-9_-]+$/i.test(chapter.step)
        || seenSteps.has(chapter.step) || typeof chapter.title !== 'string' || !chapter.title.trim()
        || chapter.title.length > 150 || typeof chapter.start_seconds !== 'number'
        || !Number.isFinite(chapter.start_seconds) || chapter.start_seconds < 0
        || typeof chapter.file !== 'string' || chapter.file !== chapter.file.trim()
        || !/^[^/\\?#\u0000-\u001f]+\.(mp4|webm|m4v)$/i.test(chapter.file)) {
        throw new Error('Invalid chapter');
      }
      seenSteps.add(chapter.step);
      return { ...chapter, title: chapter.title.trim(), url: new URL(encodeURIComponent(chapter.file), videoDirectory) };
    });
  }

  function renderChapters(chapters, availability) {
    chapterItems = [];
    chapterList.replaceChildren();
    chapters.forEach((chapter, index) => {
      const row = document.createElement('li');
      row.className = 'watch-chapter-row';
      const button = document.createElement('button');
      button.type = 'button';
      button.className = 'watch-chapter-jump';
      const number = document.createElement('span');
      number.className = 'watch-chapter-number';
      number.textContent = String(index + 1).padStart(2, '0');
      number.setAttribute('aria-hidden', 'true');
      const title = document.createElement('span');
      title.className = 'watch-chapter-title';
      title.textContent = chapter.title;
      const time = document.createElement('span');
      time.className = 'watch-chapter-time';
      time.textContent = formatTime(chapter.start_seconds);
      button.append(number, title, time);
      button.addEventListener('click', () => {
        if (!fullVideoReady) return;
        if (chapter.start_seconds >= player.duration) {
          chapterFeedback.textContent = '这一章节的位置暂不可用，请先从完整视频观看。';
          return;
        }
        player.currentTime = chapter.start_seconds;
        playerNote.textContent = `正在观看：${chapter.title}`;
        chapterFeedback.textContent = `已跳到 ${formatTime(chapter.start_seconds)}：${chapter.title}`;
        player.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'center' });
        player.focus({ preventScroll: true });
        player.play().catch(() => { playerNote.textContent = `已定位到「${chapter.title}」，点击播放继续观看。`; });
      });
      row.append(button);
      if (availability[index] === 'available') {
        const clip = document.createElement('a');
        clip.className = 'watch-chapter-clip';
        clip.href = chapter.url.href;
        clip.target = '_blank';
        clip.rel = 'noopener noreferrer';
        clip.setAttribute('aria-label', `单独观看：${chapter.title}（新标签页）`);
        clip.textContent = '单独观看';
        const arrow = document.createElement('span');
        arrow.textContent = '↗';
        arrow.setAttribute('aria-hidden', 'true');
        clip.append(arrow);
        row.append(clip);
      } else {
        const pending = document.createElement('span');
        pending.className = 'watch-clip-pending';
        pending.textContent = availability[index] === 'missing' ? '片段待发布' : '片段暂不可用';
        row.append(pending);
      }
      chapterItems.push({ button, start: chapter.start_seconds, title: chapter.title });
      chapterList.append(row);
    });
    chaptersPending.hidden = true;
    chapterList.hidden = false;
    updateChapterButtons();
  }

  async function loadChapters() {
    try {
      const response = await fetchWithTimeout(chapterDataUrl);
      if (response.status === 404 || response.status === 410) {
        showChapterPending(true);
        return;
      }
      if (!response.ok) throw new Error('Chapter list unavailable');
      const chapters = parseChapters(await response.json());
      if (!chapters.length) {
        showChapterPending(true);
        return;
      }
      const availability = await Promise.all(chapters.map((chapter) => checkVideo(chapter.url)));
      renderChapters(chapters, availability);
    } catch {
      showChapterPending(false);
    }
  }

  async function refreshMedia() {
    if (refreshInProgress) return;
    refreshInProgress = true;
    retryButton.disabled = true;
    chapterFeedback.textContent = '';
    try {
      await Promise.all([loadFullVideo(), loadChapters()]);
    } finally {
      refreshInProgress = false;
      retryButton.disabled = false;
    }
  }

  player.addEventListener('timeupdate', () => {
    let active = null;
    for (const item of chapterItems) {
      if (item.start <= player.currentTime && (!active || item.start > active.start)) active = item;
    }
    for (const item of chapterItems) {
      if (item === active) item.button.setAttribute('aria-current', 'true');
      else item.button.removeAttribute('aria-current');
    }
  });
  player.addEventListener('error', () => { if (fullVideoReady) setVideoUnavailable(false); });
  retryButton.addEventListener('click', refreshMedia);
  refreshMedia();
})();

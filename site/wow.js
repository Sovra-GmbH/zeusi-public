// zeusi.ai: the "wow" layer. Progressive enhancement only, loaded with defer; same origin, no request of its
// own (the film files are loaded by the browser's video elements: the loop only on scroll-in with motion
// allowed, the full film only on "Watch with sound"), no third party, no HTML injection, no string-to-code. Without this file: the poster and "Film coming soon" (or "Turn on
// JavaScript to play the film") show, the full startup reply is plain text, the example cards are static,
// and there are no paw prints (no mouse trail, no tap paw).
(function () {
  'use strict';

  var mq = function (q) { return !!(window.matchMedia && window.matchMedia(q).matches); };
  var reduce = mq('(prefers-reduced-motion: reduce)');
  var hasIO = 'IntersectionObserver' in window;

  function onceVisible(el, threshold, cb) {
    if (!hasIO) { cb(); return; }
    var io = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) { io.disconnect(); cb(); return; }
      }
    }, { threshold: threshold });
    io.observe(el);
  }

  // ---------------------------------------------------------------------------------------------
  // 1. The hero film. ONE config point: the data-*-src paths on #film (index.html; files in assets/film/):
  //    data-poster-src, data-loop-webm-src, data-loop-mp4-src, data-sound-src, data-captions-src.
  //    data-sound-src is the one absolute URL: the full film's public Blob object, which answers every HTTP
  //    Range request exactly (a same-origin rewrite to it cached one range slice and broke iOS Safari).
  //    - The muted, looping PREVIEW is a <video> with <source> WebM first, then MP4. It is made only when the
  //      slot scrolls in AND motion is allowed AND the browser does not ask to save data (preload="none" until
  //      then); it pauses when the slot leaves the screen. It never carries the full film.
  //    - "Watch with sound" does NOT unmute the preview (the preview is a short loop, not the explainer). It
  //      drops the preview and makes a SECOND <video> whose src is data-sound-src: the full film is requested
  //      for the first time on that click or key press, never on load, scroll or preview. It plays with sound,
  //      native controls and the optional captions track.
  //    - While the preview plays, a "Pause preview" / "Play preview" button (always visible, not only on hover)
  //      stops and restarts it (WCAG 2.2.2); a preview the user paused stays paused on scroll-in.
  //    - Reduced motion: never autoplay; the poster and "Watch with sound" stay until the user presses it.
  //    - Empty data-sound-src: no button, CSS shows "Film coming soon". A preview that fails is simply removed
  //      (the poster stays); a full film that fails shows "The film could not be loaded."
  //    Every video is inserted BELOW the overlay (and CSS stacks the overlay above it), so "Watch with sound"
  //    stays the hit target and its focus ring stays visible while the preview plays.
  (function film() {
    var root = document.getElementById('film');
    if (!root) return;
    var attr = function (n) { return (root.getAttribute(n) || '').trim(); };
    var soundSrc = attr('data-sound-src');
    var loopSrcs = [[attr('data-loop-webm-src'), 'video/webm'], [attr('data-loop-mp4-src'), 'video/mp4']]
      .filter(function (s) { return !!s[0]; });
    if (!soundSrc && loopSrcs.length === 0) return;
    var captions = attr('data-captions-src');
    var frame = root.querySelector('.film-frame');
    var button = root.querySelector('.film-play');
    var overlay = root.querySelector('.film-overlay');
    var pause = root.querySelector('.film-pause');
    var posterImg = root.querySelector('.film-poster');
    var posterSrc = attr('data-poster-src') || (posterImg ? posterImg.currentSrc || posterImg.src : '');
    var status = document.getElementById('film-status');
    if (!frame || !button) return;
    root.classList.add('film-ready');
    button.hidden = !soundSrc;

    var loop = null;   // the muted preview
    var full = null;   // the full film with sound (made on the first click only)
    var failed = false;
    var userPaused = false;
    var saveData = !!(navigator.connection && navigator.connection.saveData);

    function say(msg) { if (status) status.textContent = msg; }

    function below(v) { frame.insertBefore(v, overlay && overlay.parentNode === frame ? overlay : frame.firstChild); }

    // The preview's pause control follows the preview's real state (a blocked autoplay or a scroll-away pause
    // shows "Play preview"); it is hidden once the film plays with sound (native controls) or fails.
    function sync() {
      if (!pause) return;
      pause.hidden = !loop || failed || root.classList.contains('film-sound');
      pause.textContent = loop && !loop.paused ? 'Pause preview' : 'Play preview';
    }

    function makeLoop() {
      if (loop) return loop;
      var v = document.createElement('video');
      v.className = 'film-video film-loop';
      v.setAttribute('playsinline', '');
      v.preload = 'none';
      v.muted = true;
      v.loop = true;
      if (posterSrc) v.poster = posterSrc;
      // WebM first, MP4 as the fallback: the browser loads the first it can play. Only the loop files here.
      var last = null;
      for (var i = 0; i < loopSrcs.length; i++) {
        var s = document.createElement('source');
        s.src = loopSrcs[i][0];
        s.type = loopSrcs[i][1];
        v.appendChild(s);
        last = s;
      }
      if (last) last.addEventListener('error', dropLoop);  // every source failed
      v.addEventListener('error', dropLoop);
      v.addEventListener('play', sync);
      v.addEventListener('pause', sync);
      loop = v;
      below(v);
      return v;
    }

    // Stop the preview and its download, and take it out (the poster shows again).
    function dropLoop() {
      if (!loop) return;
      var v = loop;
      loop = null;
      try { v.pause(); } catch (e) { /* already stopped */ }
      while (v.firstChild) v.removeChild(v.firstChild);
      v.removeAttribute('src');
      try { v.load(); } catch (e) { /* nothing to abort */ }
      if (v.parentNode) v.parentNode.removeChild(v);
      root.classList.remove('film-playing');
      sync();
    }

    // The full film. Called from the button handler only: this is the first and only place the
    // data-sound-src path reaches the page.
    function makeFull() {
      if (full) return full;
      var v = document.createElement('video');
      v.className = 'film-video film-full';
      v.setAttribute('playsinline', '');
      v.preload = 'none';
      v.controls = true;
      if (posterSrc) v.poster = posterSrc;
      if (captions) {
        var track = document.createElement('track');
        track.kind = 'captions';
        track.src = captions;
        track.srclang = attr('data-captions-lang') || 'en';
        track.label = attr('data-captions-label') || 'Captions';
        track.default = true;
        v.appendChild(track);
      }
      v.addEventListener('error', fail);
      v.src = soundSrc;
      full = v;
      below(v);
      return v;
    }

    function fail() {
      if (failed) return;
      failed = true;
      dropLoop();
      if (full && full.parentNode) full.parentNode.removeChild(full);
      full = null;
      root.classList.remove('film-playing', 'film-sound');
      root.classList.add('film-failed');
      button.hidden = true;
      if (pause) pause.hidden = true;
      say('The film could not be loaded.');
    }

    function play(v, onError) {
      var p = v.play();
      if (p && p.catch) p.catch(function (e) { if (e && e.name !== 'AbortError' && e.name !== 'NotAllowedError') onError(); });
    }

    button.addEventListener('click', function () {
      if (failed || !soundSrc) return;
      dropLoop();
      var v = makeFull();
      v.muted = false;
      root.classList.add('film-playing', 'film-sound');
      button.hidden = true;
      if (pause) pause.hidden = true;
      play(v, fail);
      v.focus();
      say('Playing the film with sound.');
    });

    if (reduce || saveData || !hasIO || loopSrcs.length === 0) return;

    if (pause) {
      pause.addEventListener('click', function () {
        if (failed || !loop || root.classList.contains('film-sound')) return;
        if (loop.paused) {
          userPaused = false;
          root.classList.add('film-playing');
          play(loop, dropLoop);
          say('Preview playing.');
        } else {
          userPaused = true;
          loop.pause();
          say('Preview paused.');
        }
      });
    }

    var io = new IntersectionObserver(function (entries) {
      var e = entries[entries.length - 1];
      if (failed) { io.disconnect(); return; }
      if (e.isIntersecting) {
        if (root.classList.contains('film-sound') || userPaused) return;
        var v = makeLoop();
        root.classList.add('film-playing');
        play(v, dropLoop);
        sync();
      } else if (loop && !root.classList.contains('film-sound')) {
        loop.pause();
      }
    }, { threshold: 0.35 });
    io.observe(root);
  })();

  // ---------------------------------------------------------------------------------------------
  // 2. The startup terminal. The static <pre class="term-full"> holds the server's exact reply: it is
  //    the copy screen readers read (once) and it reserves the final size. On scroll-in, an aria-hidden
  //    overlay types the same lines; the static text is made transparent (still in the accessibility
  //    tree and the layout) until typing ends. Reduced motion: nothing runs, the full text is shown.
  (function terminal() {
    var term = document.querySelector('[data-term]');
    if (!term || reduce) return;
    var screen = term.querySelector('.term-screen');
    var full = term.querySelector('.term-full');
    var replay = term.querySelector('.term-replay');
    if (!screen || !full) return;
    var lines = Array.prototype.slice.call(full.querySelectorAll('.tl'));
    if (lines.length === 0) return;

    var overlay = null;
    var timer = 0;

    function stop() {
      window.clearTimeout(timer);
      if (overlay && overlay.parentNode) overlay.parentNode.removeChild(overlay);
      overlay = null;
      screen.classList.remove('typing');
      if (replay) { replay.textContent = 'Replay'; replay.hidden = false; }
    }

    function run() {
      stop();
      overlay = document.createElement('pre');
      overlay.className = 'term-typed';
      overlay.setAttribute('aria-hidden', 'true');
      var code = document.createElement('code');
      overlay.appendChild(code);
      screen.appendChild(overlay);
      screen.classList.add('typing');
      if (replay) { replay.textContent = 'Show all'; replay.hidden = false; }

      var li = 0;
      var span = null;
      var text = '';
      var at = 0;

      function step() {
        if (!overlay) return;
        if (span === null) {
          if (li >= lines.length) { stop(); return; }
          if (li > 0) code.appendChild(document.createTextNode('\n'));
          span = document.createElement('span');
          span.className = lines[li].className;
          code.appendChild(span);
          text = lines[li].textContent || '';
          at = 0;
        }
        // Each line takes at most ~0.3 s whatever its length; the reply is typed line by line.
        var chunk = Math.max(2, Math.ceil(text.length / 18));
        at = Math.min(text.length, at + chunk);
        // The caret is a text character (text never counts as a layout shift; a moving element would).
        span.textContent = text.slice(0, at) + (at < text.length ? '\u258D' : '');
        if (at >= text.length) {
          span = null;
          li++;
          timer = window.setTimeout(step, li === 1 ? 420 : text.length === 0 ? 40 : 90);
        } else {
          timer = window.setTimeout(step, 16);
        }
      }
      step();
    }

    if (replay) {
      replay.addEventListener('click', function () {
        if (overlay) stop(); else run();
      });
    }
    onceVisible(term, 0.3, run);
  })();

  // ---------------------------------------------------------------------------------------------
  // 3. Paw prints. Fine pointers (mouse, pen): a light trail behind the pointer anywhere on the page.
  //    Touch and other non-mouse, non-pen pointers: every tap (a pointerdown and pointerup that moved
  //    less than TAP px; a scroll or a pointercancel never counts) flashes one paw at the tap point with
  //    a quick soft amber glow that fades. A finger drag leaves no trail and a mouse click no tap paw.
  //    Never under reduced motion. Every listener is passive and only reads the event: nothing here
  //    cancels, stops or redirects it, so taps, links, focus and scrolling work as before. The prints
  //    live in one fixed, pointer-events:none, aria-hidden layer (no layout shift, no effect on clicks
  //    or focus); each is removed when its fade ends, with a timer as backstop (at most 12 at a time).
  (function paws() {
    if (reduce) return;
    var layer = null;
    var last = null;
    var down = null;
    var left = false;
    var MAX = 12;
    var STEP = 26;
    var TAP = 14;
    var passive = { passive: true };

    function fine(ev) { return ev.pointerType === 'mouse' || ev.pointerType === 'pen'; }

    function place(node, x, y, r) {
      if (!layer) {
        layer = document.createElement('div');
        layer.className = 'paw-layer';
        layer.setAttribute('aria-hidden', 'true');
        document.body.appendChild(layer);
      }
      while (layer.childNodes.length >= MAX) layer.removeChild(layer.firstChild);
      node.style.setProperty('--x', x.toFixed(1) + 'px');
      node.style.setProperty('--y', y.toFixed(1) + 'px');
      node.style.setProperty('--r', r.toFixed(1) + 'deg');
      var gone = function () { if (node.parentNode) node.parentNode.removeChild(node); };
      node.addEventListener('animationend', gone);
      window.setTimeout(gone, 1500);
      layer.appendChild(node);
    }

    function print(cls) {
      var paw = document.createElement('span');
      paw.className = cls;
      return paw;
    }

    // Fine pointer: one print every STEP px of travel, alternating left and right of the path.
    function drop(x, y, angle) {
      left = !left;
      var off = left ? -6 : 6;
      var rad = (angle + 90) * Math.PI / 180;
      place(print('paw'), x + Math.cos(rad) * off, y + Math.sin(rad) * off, angle + 90);
    }

    // Touch: a glow under one paw, both centred on the tap point.
    function tap(x, y) {
      left = !left;
      place(print('paw-glow'), x, y, 0);
      place(print('paw paw-tap'), x, y, left ? -12 : 12);
    }

    function move(ev) {
      if (!fine(ev)) {
        if (down && ev.pointerId === down.id) {
          var mx = ev.clientX - down.x;
          var my = ev.clientY - down.y;
          if (mx * mx + my * my > TAP * TAP) down = null;
        }
        return;
      }
      var x = ev.clientX;
      var y = ev.clientY;
      if (last === null) { last = { x: x, y: y }; return; }
      var dx = x - last.x;
      var dy = y - last.y;
      if (dx * dx + dy * dy < STEP * STEP) return;
      drop(x, y, Math.atan2(dy, dx) * 180 / Math.PI);
      last = { x: x, y: y };
    }

    function press(ev) {
      down = (fine(ev) || ev.isPrimary === false) ? null : { id: ev.pointerId, x: ev.clientX, y: ev.clientY };
    }

    function release(ev) {
      var d = down;
      down = null;
      if (!d || fine(ev) || ev.pointerId !== d.id) return;
      var dx = ev.clientX - d.x;
      var dy = ev.clientY - d.y;
      if (dx * dx + dy * dy > TAP * TAP) return;
      tap(ev.clientX, ev.clientY);
    }

    document.addEventListener('pointermove', move, passive);
    document.addEventListener('pointerdown', press, passive);
    document.addEventListener('pointerup', release, passive);
    document.addEventListener('pointercancel', function () { down = null; }, passive);
    document.addEventListener('pointerout', function (ev) { if (!ev.relatedTarget) last = null; }, passive);
  })();

  // ---------------------------------------------------------------------------------------------
  // 4. "What Zeusi remembers": the example cards flip in as they scroll into view. Without JS, without
  //    IntersectionObserver, or under reduced motion they are simply shown.
  (function reveal() {
    var cards = document.querySelectorAll('[data-reveal]');
    if (cards.length === 0 || reduce || !hasIO) return;
    var io = new IntersectionObserver(function (entries) {
      for (var i = 0; i < entries.length; i++) {
        if (entries[i].isIntersecting) {
          entries[i].target.classList.add('revealed');
          io.unobserve(entries[i].target);
        }
      }
    }, { threshold: 0.2, rootMargin: '0px 0px -8% 0px' });
    for (var i = 0; i < cards.length; i++) {
      cards[i].classList.add('reveal-ready');
      io.observe(cards[i]);
    }
  })();
})();

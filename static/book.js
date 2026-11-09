/* Step-by-step booking form. The server re-checks EVERYTHING; these checks
   are only for a smooth experience. */
(function () {
  "use strict";

  /* ── Program label map ──────────────────────────────────────────────────
     Maps the short program keys (from the server) to their full names.
     "BS " prefix is handled by the helper below; non-BS programs are
     listed with their full name explicitly.                                */
  var PROG_LABELS = {
    "BSEd VERE":    "Bachelor of Secondary Education — Values Education, Religious Education",
    "BS Accountancy": "Bachelor of Science in Accountancy",
    "AIS":          "Bachelor of Science in Accounting Information System",
    "BA":           "Bachelor of Science in Business Administration",
    "BS Nursing":   "Bachelor of Science in Nursing",
    "BS HM":        "Bachelor of Science in Hospitality Management",
    "BS TM":        "Bachelor of Science in Tourism Management",
    "BS Pharmacy":  "Bachelor of Science in Pharmacy",
    "BS ARCH":      "Bachelor of Science in Architecture",
    "BS CE":        "Bachelor Of Science in Civil Engineering",
    "BS CoE":       "Bachelor of Science in Computer Engineering",
    "BS IE":        "Bachelor of Science in Industrial Engineering",
    "Human Services": "Bachelor of Science in Human Services",
    "AB Comm":      "Bachelor of Arts in Communication",
    "BS Psychology":"Bachelor of Science in Psychology",
    "Criminology":  "Bachelor of Science in Criminology",
    "IT":           "Bachelor of Science in Information Technology"
  };

  function progLabel(key) {
    return PROG_LABELS[key] || key;
  }

  var root = document.querySelector(".card[data-cfg]");
  if (!root) return;
  var submit = root.querySelector('button[id="book"]');
  var cfg = JSON.parse(root.dataset.cfg);
  var csrf = document.querySelector("meta[name=csrf]").content;
  var S = { svc: null, day: null, time: null, label: "", ver: false, step: 1 };

  function $(i) { return document.getElementById(i); }

  function api(path, body) {
    var o = { method: body ? "POST" : "GET", headers: { "X-CSRF-Token": csrf } };
    if (body) { o.headers["Content-Type"] = "application/json"; o.body = JSON.stringify(body); }
    return fetch(path, o).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { j.status = r.status; return j; });
    });
  }

  function chips(id, items, sel, on, dis) {
    var c = $(id); c.innerHTML = "";
    items.forEach(function (it) {
      var b = document.createElement("button");
      b.type = "button"; b.className = "chip"; b.textContent = it[1];
      b.setAttribute("aria-pressed", String(sel === it[0]));
      if (dis && dis(it)) b.disabled = true;
      b.onclick = function () { on(it); };
      c.appendChild(b);
    });
  }

  function prog() { return $("prog").value; }

  function drawChoices() {
    var p = prog();
    $("bw").textContent = p
      ? "Your assigned counselor: " + cfg.programs[p]
      : "Choose your program to see your assigned counselor.";

    chips("svc", Object.keys(cfg.services).map(function (k) {
      return [k, k + " (" + cfg.services[k] + " mins)"];
    }), S.svc, function (it) { S.svc = it[0]; S.time = null; drawChoices(); });

    chips("days", cfg.days.map(function (d) { return [d.iso, d.label]; }),
      S.day, function (it) { S.day = it[0]; S.time = null; drawChoices(); });

    if (!p || !S.svc || !S.day) {
      $("slots").textContent = "Choose a service and a date to see open times.";
      return;
    }

    api("/api/slots?program=" + encodeURIComponent(p) +
        "&service=" + encodeURIComponent(S.svc) + "&day=" + S.day)
      .then(function (j) {
        if (!j.slots) { $("slots").textContent = j.error || "Could not load times."; return; }
        chips("slots", j.slots.map(function (s) { return [s.start, s.label, s.free]; }),
          S.time, function (it) { S.time = it[0]; S.label = it[1]; drawChoices(); },
          function (it) { return !it[2]; });
      });
  }

  /* ── Build the program <select> with full names ─────────────────────── */
  var sel = $("prog");
  sel.innerHTML = '<option value="">Select your program</option>';
  Object.keys(cfg.programs).forEach(function (p) {
    var o = document.createElement("option");
    o.value = p;
    o.textContent = progLabel(p);   // ← full name in the dropdown
    sel.appendChild(o);
  });
  sel.onchange = function () { S.time = null; drawChoices(); };

  $("em").oninput = function () { S.ver = false; $("cmsg").textContent = ""; };

  $("sendc").onclick = function () {
    $("cmsg").textContent = "Sending…";
    api("/api/send-code", { email: $("em").value }).then(function (j) {
      $("cmsg").textContent = j.ok
        ? "Code sent. Check your inbox (valid for 5 minutes)."
        : (j.error || "Could not send.");
    });
  };

  $("verc").onclick = function () {
    api("/api/verify-code", { email: $("em").value, code: $("vc").value }).then(function (j) {
      S.ver = !!j.ok;
      $("cmsg").textContent = j.ok ? "Email verified." : (j.error || "Wrong code.");
    });
  };

  function chk(s) {
    var n = $("nm").value.trim(), i = $("sid").value.trim(), ph = $("ph").value.replace(/[\s-]/g, "");
    if (s === 1) {
      if (n.length < 2)                        return "Enter your full name.";
      if (!/^[0-9-]{4,15}$/.test(i))           return "Enter a valid student number (numbers only).";
      if (!prog())                              return "Select your program.";
      if (!$("sec").value.trim())               return "Enter your section.";
    }
    if (s === 2) {
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test($("em").value.trim()))
                                                return "Enter a valid email address.";
      if (!/^(09|\+639)\d{9}$/.test(ph))        return "Enter a valid phone number, like 09123456789.";
      if (!S.ver)                               return "Send a code to your email, enter it, and press Verify.";
    }
    if (s === 3 && (!S.svc || !S.day || S.time === null))
                                                return "Choose a service, date, and time.";
    return "";
  }

  function rows() {
    var p = prog(), i = $("sid").value.trim();
    return [
      ["Name",               $("nm").value.trim()],
      ["Student number",     "*****" + i.slice(-3)],
      ["Program and section", progLabel(p) + " — " + $("sec").value.trim()],
      ["Counselor",          cfg.programs[p]],
      ["Service",            S.svc + " (" + cfg.services[S.svc] + " mins)"],
      ["Date",               cfg.days.filter(function (d) { return d.iso === S.day; })[0].label],
      ["Starts at",          S.label]
    ];
  }

  function step(n) {
    S.step = n;
    for (var k = 1; k <= 4; k++) {
      $(("s" + k)).hidden = k !== n;
      $(("p" + k)).className = k === n ? "on" : k < n ? "done" : "";
    }
    $("next").hidden = n === 4;
    submit.hidden = n !== 4;
    $("err").textContent = "";
    window.scrollTo(0, 0);
    if (n === 3) drawChoices();
    if (n === 4) {
      var rv = $("rv"); rv.innerHTML = "";
      rows().forEach(function (r) {
        var d = document.createElement("div"); d.className = "item";
        var a = document.createElement("span"), b = document.createElement("span");
        a.textContent = r[0]; b.textContent = r[1]; d.appendChild(a); d.appendChild(b); rv.appendChild(d);
      });
    }
  }

  $("next").onclick = function () {
    var m = chk(S.step);
    if (m) $("err").textContent = m;
    else step(S.step + 1);
  };
  $("back").onclick = function () {
    if (S.step === 1) location.href = "/";
    else step(S.step - 1);
  };

  submit.onclick = function () {
    for (var s = 1; s <= 3; s++) {
      var m = chk(s);
      if (m) { step(s); $("err").textContent = m; return; }
    }
    if (!$("cons").checked) { $("err").textContent = "Please agree to the data privacy notice."; return; }
    submit.disabled = true;
    api("/api/book", {
      name: $("nm").value, student_no: $("sid").value, section: $("sec").value,
      program: prog(), email: $("em").value, phone: $("ph").value,
      service: S.svc, day: S.day, start: S.time, note: $("nt").value, consent: true
    }).then(function (j) {
      submit.disabled = false;
      if (j.ok) { location.href = "/receipt/" + j.ref; return; }
      $("err").textContent = j.error || "Could not book. Please try again.";
      if (j.status === 409) { S.time = null; step(3); $("err").textContent = j.error; }
    });
  };

  drawChoices();
  step(1);
})();
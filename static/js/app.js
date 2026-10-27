/**
 * AEGISAGENT CYBER DEFENSE - SOC DASHBOARD FRONTEND LOGIC
 * High-performance WebSocket streaming, real-time Canvas telemetry,
 * interactive attack simulation, and deep AI explainability forensics.
 */

(function () {
  'use strict';

  // ─────────────────────────────────────────
  // STATE MANAGEMENT
  // ─────────────────────────────────────────
  const state = {
    ws: null,
    isStreaming: false,
    streamDelay: 0.08,
    autonomousMode: true,
    filter: 'all',
    packets: [],
    maxPackets: 80,
    telemetryPoints: [],
    maxTelemetryPoints: 60,
    taxonomy: {},
    blockedIps: [],
    incidents: [],
    alerts: [],
    modelHistory: [],
    selectedPacket: null,
    oodaPhase: 'OBSERVE',
  };

  // ─────────────────────────────────────────
  // DOM ELEMENT REFERENCES
  // ─────────────────────────────────────────
  const el = {
    // Nav & Controls
    btnPlayPause: document.getElementById('btnPlayPause'),
    playPauseIcon: document.getElementById('playPauseIcon'),
    playPauseText: document.getElementById('playPauseText'),
    btnReset: document.getElementById('btnReset'),
    autoModeToggle: document.getElementById('autoModeToggle'),
    modeStatusText: document.getElementById('modeStatusText'),
    btnExportReport: document.getElementById('btnExportReport'),
    wsIndicator: document.getElementById('wsIndicator'),
    wsLabel: document.getElementById('wsLabel'),
    modelVersionBadge: document.getElementById('modelVersionBadge'),
    speedBtns: document.querySelectorAll('.speed-btn'),

    // Hero KPI
    valPackets: document.getElementById('valPackets'),
    valThroughput: document.getElementById('valThroughput'),
    valLatency: document.getElementById('valLatency'),
    valAccuracy: document.getElementById('valAccuracy'),
    valF1: document.getElementById('valF1'),
    valAttacks: document.getElementById('valAttacks'),
    valNormal: document.getElementById('valNormal'),
    valAgentStatus: document.getElementById('valAgentStatus'),
    valOodaPhase: document.getElementById('valOodaPhase'),
    valCurrentConf: document.getElementById('valCurrentConf'),
    valBaselineConf: document.getElementById('valBaselineConf'),
    valBlockedCount: document.getElementById('valBlockedCount'),
    valAdaptations: document.getElementById('valAdaptations'),
    accuracyFill: document.getElementById('accuracyFill'),
    confProgressFill: document.getElementById('confProgressFill'),

    // Operations / Terminal / Gauges
    thoughtConsole: document.getElementById('thoughtConsole'),
    gaugeCurrentConf: document.getElementById('gaugeCurrentConf'),
    gaugeBaselineConf: document.getElementById('gaugeBaselineConf'),
    gaugeDriftDrop: document.getElementById('gaugeDriftDrop'),
    gaugeAdaptCount: document.getElementById('gaugeAdaptCount'),
    oodaObserve: document.getElementById('oodaObserve'),
    oodaOrient: document.getElementById('oodaOrient'),
    oodaDecide: document.getElementById('oodaDecide'),
    oodaAct: document.getElementById('oodaAct'),
    attackBtns: document.querySelectorAll('.attack-trigger-btn'),
    btnTriggerDrift: document.getElementById('btnTriggerDrift'),
    btnManualAdapt: document.getElementById('btnManualAdapt'),

    // Visual Analytics
    confidenceCanvas: document.getElementById('confidenceCanvas'),
    taxonomyBars: document.getElementById('taxonomyBars'),

    // Packet Table
    packetTableBody: document.getElementById('packetTableBody'),
    filterBtns: document.querySelectorAll('.filter-pill'),

    // Defense & Audits
    quarantineList: document.getElementById('quarantineList'),
    badgeQuarantineCount: document.getElementById('badgeQuarantineCount'),
    alertsList: document.getElementById('alertsList'),
    badgeIncidentCount: document.getElementById('badgeIncidentCount'),
    evolutionList: document.getElementById('evolutionList'),
    badgeModelVersion: document.getElementById('badgeModelVersion'),

    // Modal
    modalBackdrop: document.getElementById('modalBackdrop'),
    modalCloseBtn: document.getElementById('modalCloseBtn'),
    modalDismissBtn: document.getElementById('modalDismissBtn'),
    modalQuarantineBtn: document.getElementById('modalQuarantineBtn'),
    modalTitle: document.getElementById('modalTitle'),
    modalSubtitle: document.getElementById('modalSubtitle'),
    modalVerdictLabel: document.getElementById('modalVerdictLabel'),
    modalAttackType: document.getElementById('modalAttackType'),
    modalConfVal: document.getElementById('modalConfVal'),
    modalAnomalyVal: document.getElementById('modalAnomalyVal'),
    modalReasoningText: document.getElementById('modalReasoningText'),
    modalMitreSection: document.getElementById('modalMitreSection'),
    modalMitreId: document.getElementById('modalMitreId'),
    modalMitreName: document.getElementById('modalMitreName'),
    modalSeverity: document.getElementById('modalSeverity'),
    modalMitreDesc: document.getElementById('modalMitreDesc'),
    modalFirewallRule: document.getElementById('modalFirewallRule'),
    modalFeaturesList: document.getElementById('modalFeaturesList'),
    toastContainer: document.getElementById('toastContainer'),
  };

  // Canvas 2D context
  let canvasCtx = el.confidenceCanvas ? el.confidenceCanvas.getContext('2d') : null;

  // ─────────────────────────────────────────
  // WEBSOCKET CLIENT & MESSAGING
  // ─────────────────────────────────────────
  function initWebSocket() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const wsUrl = `${protocol}//${window.location.host}/ws/stream`;

    el.wsLabel.textContent = 'CONNECTING...';
    el.wsIndicator.classList.remove('connected');

    try {
      state.ws = new WebSocket(wsUrl);

      state.ws.onopen = () => {
        el.wsLabel.textContent = 'LIVE';
        el.wsIndicator.classList.add('connected');
        showToast('✅ Connected — AegisAgent is watching your network', 'success');
      };

      state.ws.onmessage = (event) => {
        try {
          const data = JSON.parse(event.data);
          handleWebSocketMessage(data);
        } catch (e) {
          console.error('[WS Parse Error]', e);
        }
      };

      state.ws.onclose = () => {
        el.wsLabel.textContent = 'RECONNECTING';
        el.wsIndicator.classList.remove('connected');
        setTimeout(initWebSocket, 2000);
      };

      state.ws.onerror = () => {
        el.wsLabel.textContent = 'RETRYING...';
      };
    } catch (e) {
      setTimeout(initWebSocket, 2000);
    }
  }

  function sendWsCommand(action, payload = {}) {
    if (state.ws && state.ws.readyState === WebSocket.OPEN) {
      state.ws.send(JSON.stringify({ action, ...payload }));
    }
  }

  function handleWebSocketMessage(msg) {
    switch (msg.type) {
      case 'INIT_STATE':
        loadFullReport(msg.report);
        setStreamPlayingState(msg.is_streaming);
        break;

      case 'STATUS_CHANGE':
        setStreamPlayingState(msg.is_streaming);
        break;

      case 'PACKET_EVENT':
        onNewPacketEvent(msg);
        break;

      case 'SPEED_CHANGED':
        state.streamDelay = msg.delay;
        break;

      case 'INJECTION_CONFIRMED':
        showToast(`💥 Attack launched: ${msg.details.count} packets sent`, 'threat');
        appendTerminalLine('⚠ Attack', `Simulated ${msg.details.type} attack — ${msg.details.count} packets from ${msg.details.attacker_ip}`, 't-act');
        break;

      case 'DRIFT_CONFIRMED':
        showToast(`🌪️ AI is being confused — watch it recover automatically!`, 'adapt');
        appendTerminalLine('⚠ Confuse', `Unusual traffic injected. Waiting to see if the AI catches it...`, 't-ori');
        break;

      case 'ADAPTATION_TRIGGERED':
      case 'ADAPTATION_EVENT':
        handleAdaptationEvent(msg);
        break;

      case 'IP_BLOCKED':
        onIpBlocked(msg.ip, msg.details);
        break;

      case 'IP_UNBLOCKED':
        onIpUnblocked(msg.ip);
        break;

      case 'MODE_CHANGED':
        state.autonomousMode = msg.autonomous;
        el.autoModeToggle.checked = msg.autonomous;
        updateModeText();
        break;

      case 'RESET_COMPLETE':
        loadFullReport(msg.report);
        state.packets = [];
        renderPacketTable();
        showToast('✅ Reset complete — starting fresh', 'success');
        break;
    }
  }

  // ─────────────────────────────────────────
  // PACKET EVENT HANDLING
  // ─────────────────────────────────────────
  function onNewPacketEvent(data) {
    const pkt = data.packet;
    const agt = data.agent_status;
    const met = data.metrics;

    // 1. Update Hero KPI metrics
    el.valPackets.textContent = met.packets_processed.toLocaleString();
    if (met.data_source) {
      const rows = met.train_rows ? ` · ${met.train_rows.toLocaleString()} train rows` : '';
      document.getElementById('dataSourceText').textContent = `DATA: ${met.data_source.toUpperCase()}${rows}`;
    }
    if (met.accuracy === null || met.accuracy === undefined) {
      el.valAccuracy.textContent = '—';
      el.accuracyFill.style.width = '0%';
    } else {
      el.valAccuracy.textContent = (met.accuracy * 100).toFixed(1) + '%';
      el.accuracyFill.style.width = Math.min(100, Math.max(0, met.accuracy * 100)) + '%';
    }
    el.valAttacks.textContent = met.attacks_detected.toLocaleString();
    el.valNormal.textContent = met.normal_traffic.toLocaleString();
    el.valBlockedCount.textContent = met.blocked_ips_count;
    syncBlockedListIfStale(met.blocked_ips_count);
    el.valLatency.textContent = `Response: ${pkt.latency_ms.toFixed(1)}ms`;

    // 2. Update Model Version
    el.modelVersionBadge.textContent = `v${met.model_version}`;
    el.badgeModelVersion.textContent = `VERSION ${met.model_version}.0`;

    // 3. Update Agent Health & OODA state
    state.oodaPhase = agt.ooda_phase;
    updateOodaDisplay(agt.ooda_phase);

    // Friendly health labels
    const healthLabel = agt.drift_detected ? 'RELEARNING' :
      (agt.system_health === 'STABLE' ? 'HEALTHY' : agt.system_health);
    el.valAgentStatus.textContent = healthLabel;
    if (agt.drift_detected) {
      el.valAgentStatus.className = 'kpi-value status-badge-drift';
    } else {
      el.valAgentStatus.className = 'kpi-value status-badge-stable';
    }

    el.valCurrentConf.textContent = (agt.current_confidence * 100).toFixed(1) + '%';
    el.valBaselineConf.textContent = (agt.baseline_confidence * 100).toFixed(1) + '%';
    el.gaugeCurrentConf.textContent = (agt.current_confidence * 100).toFixed(1) + '%';
    el.gaugeBaselineConf.textContent = (agt.baseline_confidence * 100).toFixed(1) + '%';
    
    const drop = Math.max(0, agt.baseline_confidence - agt.current_confidence);
    el.gaugeDriftDrop.textContent = (drop * 100).toFixed(1) + '%';
    el.gaugeAdaptCount.textContent = agt.total_adaptations;
    el.valAdaptations.textContent = agt.total_adaptations;

    el.confProgressFill.style.width = Math.min(100, Math.max(0, agt.current_confidence * 100)) + '%';

    // 4. Update Agent Thought Stream if new thought
    if (agt.recent_thought) {
      appendThoughtIfNew(agt.recent_thought);
    }

    // 5. Check if adaptation event occurred in packet
    if (data.adaptation_event) {
      handleAdaptationEvent(data.adaptation_event);
    }

    // 6. Update Attack Taxonomy
    if (pkt.is_attack) {
      const type = pkt.attack_type || 'Attack';
      state.taxonomy[type] = (state.taxonomy[type] || 0) + 1;
      renderTaxonomyBars();

      if (pkt.threat_intel) {
        addOrUpdateIncident(pkt);
      }
    }

    // 7. Push telemetry point for Canvas chart
    state.telemetryPoints.push({
      conf: pkt.confidence,
      baseline: agt.baseline_confidence,
      threshold: Math.max(0, agt.baseline_confidence - 0.15),
      isAttack: pkt.is_attack,
    });
    if (state.telemetryPoints.length > state.maxTelemetryPoints) {
      state.telemetryPoints.shift();
    }
    renderConfidenceChart();

    // 8. Add packet to table
    state.packets.unshift(pkt);
    if (state.packets.length > state.maxPackets) {
      state.packets.pop();
    }
    renderPacketRow(pkt);
  }

  function handleAdaptationEvent(adapt) {
    const acc = (adapt.new_accuracy * 100).toFixed(1);
    showToast(`⚡ AI upgraded to v${adapt.model_version || 2} — now ${acc}% accurate`, 'adapt');
    appendTerminalLine('🛡 Acting', `AI retrained itself and improved to ${acc}% accuracy (Model v${adapt.model_version || 2}).`, 't-act');
    
    // Add to evolution list
    const item = document.createElement('div');
    item.className = 'evolution-item';
    item.innerHTML = `
      <div class="evo-version">AI v${adapt.model_version || 2}.0 — Auto-Upgrade</div>
      <div class="evo-details">The AI noticed its performance was dropping and automatically retrained itself. New accuracy: ${acc}% (using ${adapt.samples_used || 500} samples).</div>
      <div class="evo-meta">${new Date().toLocaleTimeString()} • Self-improvement</div>
    `;
    el.evolutionList.insertBefore(item, el.evolutionList.firstChild);
  }

  // ─────────────────────────────────────────
  // OODA DISPLAY & TERMINAL THOUGHTS
  // ─────────────────────────────────────────
  const PHASE_LABELS = {
    OBSERVE: '👁 Watching',
    ORIENT:  '🔍 Analysing',
    DECIDE:  '💡 Deciding',
    ACT:     '🛡 Acting',
  };

  function updateOodaDisplay(phase) {
    el.valOodaPhase.textContent = PHASE_LABELS[phase] || phase;
    const steps = {
      OBSERVE: el.oodaObserve,
      ORIENT: el.oodaOrient,
      DECIDE: el.oodaDecide,
      ACT: el.oodaAct,
    };

    Object.values(steps).forEach((s) => s.classList.remove('active'));
    if (steps[phase]) {
      steps[phase].classList.add('active');
    }
  }

  let lastThoughtMsg = '';
  function appendThoughtIfNew(thought) {
    if (thought.message === lastThoughtMsg) return;
    lastThoughtMsg = thought.message;

    let tagClass = 't-obs';
    if (thought.phase === 'ORIENT') tagClass = 't-ori';
    if (thought.phase === 'DECIDE') tagClass = 't-dec';
    if (thought.phase === 'ACT') tagClass = 't-act';

    const label = PHASE_LABELS[thought.phase] || thought.phase;
    appendTerminalLine(label, thought.message, tagClass);
  }

  function appendTerminalLine(tag, msg, tagClass = 't-obs') {
    const timeStr = new Date().toLocaleTimeString();
    const line = document.createElement('div');
    line.className = 'terminal-line';
    line.innerHTML = `
      <span class="t-stamp">[${timeStr}]</span>
      <span class="t-tag ${tagClass}">${tag}</span>
      <span class="t-msg">${escapeHtml(msg)}</span>
    `;
    el.thoughtConsole.appendChild(line);

    // Keep console trimmed
    while (el.thoughtConsole.children.length > 30) {
      el.thoughtConsole.removeChild(el.thoughtConsole.firstChild);
    }
    el.thoughtConsole.scrollTop = el.thoughtConsole.scrollHeight;
  }

  // ─────────────────────────────────────────
  // REAL-TIME CANVAS CHART (CONFIDENCE & DRIFT)
  // ─────────────────────────────────────────
  function renderConfidenceChart() {
    if (!canvasCtx || state.telemetryPoints.length < 2) return;

    const width = el.confidenceCanvas.parentElement.clientWidth || 600;
    const height = 190;
    el.confidenceCanvas.width = width;
    el.confidenceCanvas.height = height;

    const padding = { top: 20, right: 20, bottom: 25, left: 40 };
    const chartW = width - padding.left - padding.right;
    const chartH = height - padding.top - padding.bottom;

    canvasCtx.clearRect(0, 0, width, height);

    // Draw horizontal grid lines
    canvasCtx.strokeStyle = 'rgba(255, 255, 255, 0.05)';
    canvasCtx.lineWidth = 1;
    [0.5, 0.7, 0.85, 1.0].forEach((v) => {
      const y = padding.top + chartH * (1.0 - (v - 0.4) / 0.6);
      canvasCtx.beginPath();
      canvasCtx.moveTo(padding.left, y);
      canvasCtx.lineTo(width - padding.right, y);
      canvasCtx.stroke();

      canvasCtx.fillStyle = '#64748b';
      canvasCtx.font = '10px JetBrains Mono';
      canvasCtx.fillText((v * 100).toFixed(0) + '%', 8, y + 3);
    });

    const pts = state.telemetryPoints;
    const stepX = chartW / (state.maxTelemetryPoints - 1);

    // Helper to calculate Y from value (range: 0.4 to 1.0)
    const getY = (val) => {
      const clamped = Math.max(0.4, Math.min(1.0, val));
      return padding.top + chartH * (1.0 - (clamped - 0.4) / 0.6);
    };

    // 1. Draw Drift Threshold Line (Amber Dashed)
    canvasCtx.beginPath();
    canvasCtx.setLineDash([4, 4]);
    canvasCtx.strokeStyle = '#f59e0b';
    canvasCtx.lineWidth = 1.5;
    pts.forEach((p, i) => {
      const x = padding.left + i * stepX;
      const y = getY(p.threshold);
      if (i === 0) canvasCtx.moveTo(x, y);
      else canvasCtx.lineTo(x, y);
    });
    canvasCtx.stroke();
    canvasCtx.setLineDash([]);

    // 2. Draw Baseline Line (Emerald Safe)
    canvasCtx.beginPath();
    canvasCtx.strokeStyle = 'rgba(16, 185, 129, 0.8)';
    canvasCtx.lineWidth = 1.5;
    pts.forEach((p, i) => {
      const x = padding.left + i * stepX;
      const y = getY(p.baseline);
      if (i === 0) canvasCtx.moveTo(x, y);
      else canvasCtx.lineTo(x, y);
    });
    canvasCtx.stroke();

    // 3. Draw Confidence Line with Glow & Area Fill
    canvasCtx.beginPath();
    pts.forEach((p, i) => {
      const x = padding.left + i * stepX;
      const y = getY(p.conf);
      if (i === 0) canvasCtx.moveTo(x, y);
      else canvasCtx.lineTo(x, y);
    });

    // Stroke
    canvasCtx.strokeStyle = '#00f0ff';
    canvasCtx.lineWidth = 2.5;
    canvasCtx.shadowColor = 'rgba(0, 240, 255, 0.6)';
    canvasCtx.shadowBlur = 10;
    canvasCtx.stroke();
    canvasCtx.shadowBlur = 0;

    // 4. Draw Anomaly / Attack Dots
    pts.forEach((p, i) => {
      if (p.isAttack) {
        const x = padding.left + i * stepX;
        const y = getY(p.conf);
        canvasCtx.beginPath();
        canvasCtx.arc(x, y, 4, 0, Math.PI * 2);
        canvasCtx.fillStyle = '#f43f5e';
        canvasCtx.shadowColor = 'rgba(244, 63, 94, 0.8)';
        canvasCtx.shadowBlur = 8;
        canvasCtx.fill();
        canvasCtx.shadowBlur = 0;
      }
    });
  }

  // ─────────────────────────────────────────
  // THREAT TAXONOMY BREAKDOWN
  // ─────────────────────────────────────────
  function renderTaxonomyBars() {
    const total = Object.values(state.taxonomy).reduce((a, b) => a + b, 0);
    if (total === 0) {
      el.taxonomyBars.innerHTML = `<div class="empty-state-small">No attacks detected yet.</div>`;
      return;
    }

    const colors = {
      'DoS / SYN Flood': '#f43f5e',
      'Probe / Stealth Port Scan': '#38bdf8',
      'R2L / SSH Brute Force': '#f59e0b',
      'Data Exfiltration / C2': '#a855f7',
      'Zero-Day / Concept Drift': '#ec4899',
    };

    let html = '';
    for (const [name, count] of Object.entries(state.taxonomy)) {
      const pct = ((count / total) * 100).toFixed(0);
      const color = colors[name] || '#38bdf8';
      html += `
        <div class="taxonomy-item">
          <div class="tax-meta">
            <span class="tax-name">${escapeHtml(name)}</span>
            <span class="tax-val">${count} (${pct}%)</span>
          </div>
          <div class="tax-bar-bg">
            <div class="tax-bar-fill" style="width: ${pct}%; background-color: ${color};"></div>
          </div>
        </div>
      `;
    }
    el.taxonomyBars.innerHTML = html;
  }

  // ─────────────────────────────────────────
  // PACKET TABLE RENDERING
  // ─────────────────────────────────────────
  function renderPacketRow(pkt) {
    const emptyRow = document.getElementById('emptyRow');
    if (emptyRow) emptyRow.remove();

    // Check filter
    if (state.filter === 'attacks' && !pkt.is_attack) return;
    if (state.filter === 'normal' && pkt.is_attack) return;

    const tr = document.createElement('tr');
    tr.className = pkt.is_attack ? 'row-attack' : 'row-normal';
    tr.dataset.packetId = pkt.packet_id;

    const timeStr = new Date(pkt.timestamp).toLocaleTimeString();
    const isQuarantined = state.blockedIps.some((b) => b.ip === pkt.src_ip);

    tr.innerHTML = `
      <td>${timeStr}</td>
      <td>#${pkt.packet_id}</td>
      <td><strong>${escapeHtml(pkt.src_ip)}</strong></td>
      <td>${escapeHtml(pkt.dst_ip)}</td>
      <td>${pkt.protocol} / ${pkt.port}</td>
      <td><span class="badge-tag ${pkt.is_attack ? 'badge-attack' : 'badge-normal'}">${escapeHtml(pkt.attack_type)}</span></td>
      <td>${(pkt.confidence * 100).toFixed(1)}%</td>
      <td>${(pkt.anomaly_score * 100).toFixed(0)}%</td>
      <td>${verdictBadge(pkt, isQuarantined)}</td>
      <td><button class="filter-pill" style="padding: 2px 8px;">Details</button></td>
    `;

    tr.addEventListener('click', () => openExplainModal(pkt));

    el.packetTableBody.insertBefore(tr, el.packetTableBody.firstChild);

    // Limit table DOM rows to 50
    while (el.packetTableBody.children.length > 50) {
      el.packetTableBody.removeChild(el.packetTableBody.lastChild);
    }
  }

  function renderPacketTable() {
    el.packetTableBody.innerHTML = '';
    const filtered = state.packets.filter((p) => {
      if (state.filter === 'attacks') return p.is_attack;
      if (state.filter === 'normal') return !p.is_attack;
      return true;
    });

    if (filtered.length === 0) {
      el.packetTableBody.innerHTML = `
        <tr class="table-empty-row" id="emptyRow">
          <td colspan="10" class="text-center py-6">
            <div class="empty-state">
              <span class="empty-icon">📡</span>
              <p>No packets matching filter '${state.filter}'.</p>
            </div>
          </td>
        </tr>
      `;
      return;
    }

    filtered.forEach((p) => renderPacketRow(p));
  }

  // ─────────────────────────────────────────
  // DEEP AI EXPLAINABILITY FORENSIC MODAL
  // ─────────────────────────────────────────
  function openExplainModal(pkt) {
    state.selectedPacket = pkt;

    el.modalTitle.textContent = `Packet #${pkt.packet_id} Analysis`;
    el.modalSubtitle.textContent = `From: ${pkt.src_ip}  →  To: ${pkt.dst_ip}:${pkt.port}  (${pkt.protocol})`;

    if (pkt.is_attack) {
      el.modalVerdictLabel.textContent = '⚠️ ATTACK DETECTED';
      el.modalVerdictLabel.style.color = '#f43f5e';
      el.modalAttackType.textContent = pkt.attack_type || 'Malicious Activity';
      el.modalMitreSection.style.display = 'block';

      if (pkt.threat_intel) {
        el.modalMitreId.textContent = pkt.threat_intel.technique_id || 'T1498';
        el.modalMitreName.textContent = pkt.threat_intel.technique_name || 'Network Flood';
        const sev = pkt.threat_intel.severity || 'HIGH';
        el.modalSeverity.textContent = sev === 'CRITICAL' ? '🔴 CRITICAL' : sev === 'HIGH' ? '🟠 HIGH RISK' : '🟡 MEDIUM RISK';
        el.modalMitreDesc.textContent = pkt.threat_intel.description || 'Suspicious traffic pattern detected.';
        el.modalFirewallRule.textContent = pkt.threat_intel.firewall_rule || `Block rule applied to ${pkt.src_ip}`;
      }
    } else {
      el.modalVerdictLabel.textContent = '✅ SAFE TRAFFIC';
      el.modalVerdictLabel.style.color = '#10b981';
      el.modalAttackType.textContent = 'Normal network activity';
      el.modalMitreSection.style.display = 'none';
    }

    el.modalConfVal.textContent = (pkt.confidence * 100).toFixed(1) + '%';
    el.modalAnomalyVal.textContent = (pkt.anomaly_score * 100).toFixed(1) + '%';

    // AI Reasoning
    if (pkt.explanation && pkt.explanation.reasoning) {
      el.modalReasoningText.textContent = pkt.explanation.reasoning;
    } else {
      el.modalReasoningText.textContent = 'The AI compared this packet to thousands of training examples and made its decision based on a majority vote across 100 decision trees.';
    }

    // Features list
    let featHtml = '';
    if (pkt.explanation && pkt.explanation.top_contributing_features) {
      for (const [feat, data] of Object.entries(pkt.explanation.top_contributing_features)) {
        featHtml += `
          <div class="feat-item">
            <div class="feat-header">
              <span class="feat-name">${escapeHtml(feat)}</span>
              <span class="feat-weight">Weight: ${(data.importance * 100).toFixed(1)}% | Val: ${data.value}</span>
            </div>
            <div class="feat-desc">${escapeHtml(data.description || 'Feature metric')}</div>
          </div>
        `;
      }
    }
    el.modalFeaturesList.innerHTML = featHtml || '<div class="text-dim">No unusual signals detected — packet looks normal.</div>';

    el.modalBackdrop.classList.add('open');
  }

  function closeModal() {
    el.modalBackdrop.classList.remove('open');
    state.selectedPacket = null;
  }

  // ─────────────────────────────────────────
  // ACTIVE DEFENSE & INCIDENT MGMT
  // ─────────────────────────────────────────
  function addOrUpdateIncident(pkt) {
    const key = `${pkt.src_ip}:${pkt.attack_type}`;
    const existing = state.incidents.find((inc) => inc.src_ip === pkt.src_ip && inc.attack_type === pkt.attack_type);

    if (existing) {
      existing.packet_count = (existing.packet_count || 1) + 1;
      existing.last_seen = new Date().toLocaleTimeString();
    } else {
      state.incidents.unshift({
        src_ip: pkt.src_ip,
        attack_type: pkt.attack_type,
        technique_id: pkt.threat_intel ? pkt.threat_intel.technique_id : 'T1498',
        severity: pkt.threat_intel ? pkt.threat_intel.severity : 'HIGH',
        packet_count: 1,
        last_seen: new Date().toLocaleTimeString(),
      });
      if (state.incidents.length > 20) state.incidents.pop();
    }
    renderIncidentsList();
  }

  function renderIncidentsList() {
    el.badgeIncidentCount.textContent = `${state.incidents.length} ALERTS`;
    if (state.incidents.length === 0) {
      el.alertsList.innerHTML = `<div class="empty-state-list"><span>📋</span><p>No alerts yet. All clear.</p></div>`;
      return;
    }

    let html = '';
    state.incidents.forEach((inc) => {
      html += `
        <div class="alert-item ${inc.severity === 'MEDIUM' ? 'sev-medium' : ''}">
          <div class="a-title">${escapeHtml(inc.attack_type)} from ${escapeHtml(inc.src_ip)}</div>
          <div class="a-meta">
            <span>${inc.technique_id} · ${inc.packet_count} packets detected</span>
            <span>Last seen: ${inc.last_seen}</span>
          </div>
        </div>
      `;
    });
    el.alertsList.innerHTML = html;
  }

  function onIpBlocked(ip, details) {
    if (!state.blockedIps.some((b) => b.ip === ip)) {
      state.blockedIps.push({ ip, ...details });
    }
    el.valBlockedCount.textContent = state.blockedIps.length;
    renderQuarantineList();
    showToast(`🛡️ IP ${ip} quarantined and added to firewall blocklist`, 'threat');
    appendTerminalLine('ACTIVE_DEFENSE', `Automated iptables rule enforced: ${ip} isolated.`, 't-act');
  }

  function onIpUnblocked(ip) {
    state.blockedIps = state.blockedIps.filter((b) => b.ip !== ip);
    el.valBlockedCount.textContent = state.blockedIps.length;
    renderQuarantineList();
    showToast(`Quarantine lifted for IP ${ip}`, 'success');
  }

  // Three honest states: blocked, attack not blocked, or safe.
  function verdictBadge(pkt, isQuarantined) {
    if (isQuarantined) return '<span class="badge-tag badge-quarantined">🚫 BLOCKED</span>';
    if (pkt.is_attack) return '<span class="badge-tag badge-attack">⚠ ATTACK, NOT BLOCKED</span>';
    return '<span class="badge-tag badge-passed">✅ SAFE</span>';
  }

  // The live feed sends only a count; re-fetch the full list when the two disagree.
  let blockedSyncInFlight = false;
  function syncBlockedListIfStale(serverCount) {
    if (serverCount === state.blockedIps.length || blockedSyncInFlight) return;
    blockedSyncInFlight = true;
    fetch('/api/firewall')
      .then((r) => r.json())
      .then((list) => {
        state.blockedIps = list || [];
        el.valBlockedCount.textContent = state.blockedIps.length;
        renderQuarantineList();
      })
      .catch(() => {})
      .finally(() => { blockedSyncInFlight = false; });
  }

  function renderQuarantineList() {
    el.badgeQuarantineCount.textContent = `${state.blockedIps.length} BLOCKED`;
    if (state.blockedIps.length === 0) {
      el.quarantineList.innerHTML = `<div class="empty-state-list"><span>🛡️</span><p>No active host isolations.</p></div>`;
      return;
    }

    let html = '';
    state.blockedIps.forEach((b) => {
      html += `
        <div class="quarantine-item">
          <div class="q-info">
            <span class="q-ip">${escapeHtml(b.ip)}</span>
            <span class="q-reason">${escapeHtml(b.reason || 'Hostile traffic')}</span>
          </div>
          <button class="btn-unblock" data-ip="${escapeHtml(b.ip)}">UNBLOCK</button>
        </div>
      `;
    });
    el.quarantineList.innerHTML = html;

    // Attach unblock listeners
    el.quarantineList.querySelectorAll('.btn-unblock').forEach((btn) => {
      btn.addEventListener('click', () => {
        const ip = btn.getAttribute('data-ip');
        sendWsCommand('UNBLOCK_IP', { ip });
      });
    });
  }

  // ─────────────────────────────────────────
  // FULL REPORT LOADING (ON INIT / RECONNECT)
  // ─────────────────────────────────────────
  function loadFullReport(report) {
    if (!report) return;

    el.valPackets.textContent = report.system_info.packets_processed.toLocaleString();
    el.valAccuracy.textContent = (report.detection_metrics.accuracy * 100).toFixed(1) + '%';
    el.valAttacks.textContent = report.detection_metrics.attacks_detected.toLocaleString();
    el.valNormal.textContent = report.detection_metrics.normal_traffic.toLocaleString();
    el.valF1.textContent = report.detection_metrics.f1_score.toFixed(2);
    el.valThroughput.textContent = `${report.system_info.throughput_pps} pps`;

    if (report.agent_status) {
      el.valAgentStatus.textContent = report.agent_status.system_health;
      el.valCurrentConf.textContent = (report.agent_status.current_confidence * 100).toFixed(1) + '%';
      el.valBaselineConf.textContent = (report.agent_status.baseline_confidence * 100).toFixed(1) + '%';
      el.valAdaptations.textContent = report.agent_status.total_adaptations;
      updateOodaDisplay(report.agent_status.ooda_phase || 'OBSERVE');
    }

    state.blockedIps = report.blocked_ips || [];
    el.valBlockedCount.textContent = state.blockedIps.length;
    renderQuarantineList();

    state.taxonomy = report.attack_taxonomy || {};
    renderTaxonomyBars();

    if (report.telemetry_points && report.telemetry_points.length > 0) {
      state.telemetryPoints = report.telemetry_points.map((p) => ({
        conf: p.confidence,
        baseline: p.baseline,
        threshold: p.drift_threshold,
        isAttack: p.is_attack,
      }));
      renderConfidenceChart();
    }
  }

  // ─────────────────────────────────────────
  // UI CONTROLS & LISTENERS
  // ─────────────────────────────────────────
  function setStreamPlayingState(playing) {
    state.isStreaming = playing;
    if (playing) {
      el.btnPlayPause.classList.add('playing');
      el.playPauseIcon.textContent = '❚❚';
      el.playPauseText.textContent = 'PAUSE STREAM';
    } else {
      el.btnPlayPause.classList.remove('playing');
      el.playPauseIcon.textContent = '▶';
      el.playPauseText.textContent = 'START MONITORING';
    }
  }

  function updateModeText() {
    if (state.autonomousMode) {
      el.modeStatusText.textContent = 'AUTO';
      document.getElementById('modeDescText').textContent = 'AI acts on its own';
      el.modeStatusText.style.color = '#10b981';
    } else {
      el.modeStatusText.textContent = 'MANUAL';
      document.getElementById('modeDescText').textContent = 'You approve each action';
      el.modeStatusText.style.color = '#f59e0b';
    }
  }

  function showToast(msg, type = 'info') {
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = msg;
    el.toastContainer.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateX(40px)';
      setTimeout(() => toast.remove(), 300);
    }, 3500);
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;');
  }

  // Attach Listeners
  function attachEventListeners() {
    // Play/Pause
    el.btnPlayPause.addEventListener('click', () => {
      if (state.isStreaming) {
        sendWsCommand('PAUSE');
      } else {
        sendWsCommand('START');
      }
    });

    // Reset
    el.btnReset.addEventListener('click', () => {
      sendWsCommand('RESET');
    });

    // Speed Selector
    el.speedBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        el.speedBtns.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        const delay = parseFloat(btn.getAttribute('data-delay'));
        sendWsCommand('SET_SPEED', { delay });
      });
    });

    // Autonomous Mode Toggle
    el.autoModeToggle.addEventListener('change', (e) => {
      const isAuto = e.target.checked;
      state.autonomousMode = isAuto;
      updateModeText();
      sendWsCommand('TOGGLE_AUTONOMOUS', { autonomous: isAuto });
      showToast(isAuto ? 'Auto-Pilot Engaged: Autonomous Self-Adaptation Active' : 'Human-In-The-Loop Enabled: Manual Approval Required', 'info');
    });

    // Attack Trigger Buttons
    el.attackBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        if (btn.id === 'btnTriggerDrift' || btn.id === 'btnManualAdapt') return;
        const attackType = btn.getAttribute('data-type');
        const count = parseInt(btn.getAttribute('data-count'), 10) || 30;
        sendWsCommand('INJECT_ATTACK', { attack_type: attackType, count });
      });
    });

    // Drift Trigger Button
    el.btnTriggerDrift.addEventListener('click', () => {
      const count = parseInt(el.btnTriggerDrift.getAttribute('data-count'), 10) || 45;
      sendWsCommand('INJECT_DRIFT', { count });
    });

    // Manual Retrain Trigger Button
    el.btnManualAdapt.addEventListener('click', async () => {
      try {
        const res = await fetch('/api/adapt/trigger', { method: 'POST' });
        const data = await res.json();
        showToast(`Manual Retraining: Model incremented to v${data.model_version}`, 'success');
      } catch (e) {
        showToast('Adaptation request failed', 'threat');
      }
    });

    // Table Filter Buttons
    el.filterBtns.forEach((btn) => {
      btn.addEventListener('click', () => {
        el.filterBtns.forEach((b) => b.classList.remove('active'));
        btn.classList.add('active');
        state.filter = btn.getAttribute('data-filter');
        renderPacketTable();
      });
    });

    // Modal Actions
    el.modalCloseBtn.addEventListener('click', closeModal);
    el.modalDismissBtn.addEventListener('click', closeModal);
    el.modalBackdrop.addEventListener('click', (e) => {
      if (e.target === el.modalBackdrop) closeModal();
    });

    el.modalQuarantineBtn.addEventListener('click', () => {
      if (state.selectedPacket && state.selectedPacket.src_ip) {
        sendWsCommand('BLOCK_IP', {
          ip: state.selectedPacket.src_ip,
          reason: `Manual quarantine from Forensic Inspection #${state.selectedPacket.packet_id}`,
        });
        closeModal();
      }
    });

    // Export Forensics Button
    el.btnExportReport.addEventListener('click', () => {
      window.location.href = '/api/export/forensic';
      showToast('Downloading complete forensic incident report...', 'success');
    });

    // Window resize -> redraw chart
    window.addEventListener('resize', () => {
      renderConfidenceChart();
    });
  }

  // ─────────────────────────────────────────
  // INITIALIZATION ENTRYPOINT
  // ─────────────────────────────────────────
  window.addEventListener('DOMContentLoaded', () => {
    attachEventListeners();
    initWebSocket();
  });
})();

        window.forensicNavigationSource = null;
        document.addEventListener('DOMContentLoaded', function () {
            const body = document.body;
            const fileUploadArea = document.getElementById('file-upload-area');
            const fileInput = document.getElementById('file-input');
            const uploadBtn = document.getElementById('upload-btn');
            const uploadContainer = document.getElementById('upload-container');
            const dashboardUi = document.getElementById('dashboard-ui');

            const mainContent = document.getElementById('main-content');
            const fullscreenBtn = document.getElementById('fullscreen-btn');
            const playPauseBtn = document.getElementById('play-pause-btn');
            const replayBtn = document.getElementById('replay-btn');
            const speedBtns = document.querySelectorAll('.speed-btn');

            const procDetailsModal = document.getElementById('proc-details-modal');
            const closeProcDetailsBtn = document.getElementById('close-proc-details-btn');

            if (closeProcDetailsBtn) {
                closeProcDetailsBtn.addEventListener('click', () => {
                    procDetailsModal.classList.add('hidden');
                    if (window.forensicNavigationSource === 'mitre') {
                        switchPtTab('mitre');
                        window.forensicNavigationSource = null;
                    }
                });
            }

            window.zoomForensicCard = function(html) {
                const modal = document.getElementById('forensic-zoom-modal');
                const body = document.getElementById('zoom-modal-body');
                body.innerHTML = html;
                modal.classList.remove('hidden');
                document.body.style.overflow = 'hidden';
            };

            window.closeZoomModal = function() {
                const modal = document.getElementById('forensic-zoom-modal');
                modal.classList.add('hidden');
                document.body.style.overflow = '';
            };



            window.showProcActivity = function (pid, category) {
                if (!reportData || !reportData.behavior || !reportData.behavior.processes) return;

                const process = reportData.behavior.processes.find(p => (p.process_id || p.pid) == pid);
                if (!process) {
                    console.error("Process not found for PID:", pid);
                    return;
                }

                const title = document.getElementById('proc-details-title');
                const subtitle = document.getElementById('proc-details-subtitle');
                const content = document.getElementById('proc-details-content');
                const icon = document.getElementById('proc-details-icon');

                title.innerText = process.process_name || process.name;
                subtitle.innerText = `${category} Activity - PID: ${pid}`;

                // Set Icon
                icon.className = 'fas text-xl';
                if (category === 'FILES') { icon.classList.add('fa-file-alt', 'text-blue-400'); }
                else if (category === 'REGISTRY') { icon.classList.add('fa-key', 'text-purple-400'); }
                else if (category === 'NETWORK') { icon.classList.add('fa-network-wired', 'text-emerald-400'); }
                else if (category === 'SYSTEM') { icon.classList.add('fa-microchip', 'text-amber-400'); }

                const calls = (process.calls || []).filter(c => {
                    if (category === 'FILES') return c.category === 'filesystem';
                    if (category === 'REGISTRY') return c.category === 'registry';
                    if (category === 'NETWORK') return c.category === 'network';
                    if (category === 'SYSTEM') return c.category === 'synchronization' || c.category === 'threading' || c.category === 'system';
                    return false;
                });

                if (calls.length === 0) {
                    content.innerHTML = '<div class="text-gray-500 text-center py-10 italic">No specific calls recorded for this category.</div>';
                } else {
                    content.innerHTML = calls.map(c => `
                        <div class="activity-card">
                            <div class="flex justify-between mb-2">
                                <span class="text-indigo-300 font-bold">${c.api}</span>
                                <span class="text-gray-500 text-[10px]">${c.timestamp || ''}</span>
                            </div>
                            <div class="space-y-1">
                                ${(c.arguments || []).map(arg => `
                                    <div class="flex gap-2">
                                        <span class="text-gray-500 w-24 shrink-0">${arg.name}:</span>
                                        <span class="text-gray-300 break-all">${arg.value}</span>
                                    </div>
                                `).join('')}
                            </div>
                            ${c.return ? `<div class="mt-2 text-[10px] text-gray-500">Return: <span class="text-emerald-500">${c.return}</span></div>` : ''}
                        </div>
                    `).join('');
                }

                procDetailsModal.classList.remove('hidden');
            };
            const viewToggleBtn = document.getElementById('view-toggle-btn');
            const geolocationMapContainer = document.getElementById('geolocation-map-container');
            const visualization3dContainer = document.getElementById('visualization-3d-container');
            const worldMap = document.getElementById('world-map');
            const mapControls = document.getElementById('map-controls');
            const mapZoomInBtn = document.getElementById('map-zoom-in');
            const mapZoomOutBtn = document.getElementById('map-zoom-out');
            const mapResetBtn = document.getElementById('map-reset');
            const pTreeZoomIn = document.getElementById('ptree-zoom-in-btn');
            const pTreeZoomOut = document.getElementById('ptree-zoom-out-btn');
            const pTreeReset = document.getElementById('ptree-reset-btn');
            let pTreeScale = 1;
            function updatePTreeZoom() {
                const root = document.getElementById('ptree-root');
                if (root) {
                    root.style.transform = `scale(${pTreeScale})`;
                    root.style.transformOrigin = 'top left';
                    root.style.transition = 'transform 0.2s ease';
                }
            }
            if (pTreeZoomIn) pTreeZoomIn.addEventListener('click', () => { pTreeScale = Math.min(3, pTreeScale + 0.1); updatePTreeZoom(); });
            if (pTreeZoomOut) pTreeZoomOut.addEventListener('click', () => { pTreeScale = Math.max(0.3, pTreeScale - 0.1); updatePTreeZoom(); });
            if (pTreeReset) pTreeReset.addEventListener('click', () => { pTreeScale = 1; updatePTreeZoom(); });

            // Globe (3D real-time world) state
            let globeInstance = null;
            let globePoints = []; // {lat, lng, size, color, ip, label, time}
            let globeArcs = []; // {startLat, startLng, endLat, endLng, color}
            let useGlobe = false; // when true, show globe instead of 2D worldMap
            let lastConnection = null;
            let currentView = '3d';

            // Persistent connection path (sequence of IPs) for 2D map
            let connectionSequence = [];
            let overlaySvg = null; // SVG overlay for persistent polyline

            // Map pins by IP
            const mapPins = {};
            // Cluster elements by id
            const mapClusters = {};
            // Popup element
            let pinPopup = null;

            let reportData = null;
            let animationFrameId;
            let timelineEvents = [], nextEventIndex = 0, simulationTime = 0;
            let isPaused = false, playbackSpeed = 1.0;
            let animationStarted = false, animationEnded = false;
            let pendingView = null; // 'map' | '3d' when toggle requested mid-animation
            let geolocationData = {};
            let timelineEventsByIP = {};
            let leafletMap = null;
            let currentPolyline = null;
            // Map interaction state

            // --- File Upload Logic ---
            fileUploadArea.addEventListener('click', () => fileInput.click());
            uploadBtn.addEventListener('click', () => fileInput.click());
            replayBtn.addEventListener('click', startVisualization);

            fileInput.addEventListener('change', (e) => handleFile(e.target.files[0]));
            ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(e => fileUploadArea.addEventListener(e, p => { p.preventDefault(); p.stopPropagation(); }, false));
            fileUploadArea.addEventListener('dragenter', () => fileUploadArea.classList.add('dragover'));
            fileUploadArea.addEventListener('dragleave', () => fileUploadArea.classList.remove('dragover'));
            fileUploadArea.addEventListener('drop', (e) => {
                fileUploadArea.classList.remove('dragover');
                handleFile(e.dataTransfer.files[0]);
            });

            // If a report query param is provided, try to fetch it and load automatically
            (async function tryLoadReportFromQuery() {
                try {
                    const params = new URLSearchParams(window.location.search);
                    const reportUrl = params.get('report');
                    const reportId = params.get('report_id');
                    const isEs = params.get('es');

                    if (reportId && isEs) {
                        // Fetch from ES API
                        const token = localStorage.getItem('capeToken');
                        const resp = await fetch(`/api/es/reports/${reportId}`, {
                            headers: token ? { 'Authorization': `Bearer ${token}` } : {}
                        });
                        if (!resp.ok) throw new Error('Failed to fetch report from ES');
                        let content = await resp.text();
                        content = content.replace(/:\s*NaN\b/g, ': null').replace(/:\s*Infinity\b/g, ': null').replace(/:\s*-Infinity\b/g, ': null');
                        const json = JSON.parse(content);
                        reportData = json;
                        startVisualization();
                        return;
                    } else if (reportUrl) {
                        // attempt to fetch the report JSON (legacy/file based)
                        const resp = await fetch(reportUrl);
                        if (!resp.ok) throw new Error('Failed to fetch report');
                        let content = await resp.text();
                        content = content.replace(/:\s*NaN\b/g, ': null').replace(/:\s*Infinity\b/g, ': null').replace(/:\s*-Infinity\b/g, ': null');
                        const json = JSON.parse(content);
                        reportData = json;
                        // automatically start visualization
                        startVisualization();
                        return;
                    }
                } catch (err) {
                    console.warn('Auto-load report failed:', err);
                    alert('Failed to load report: ' + err.message);
                }
            })();

            // --- ONE-TIME UI CONTROL LISTENERS ---
            playPauseBtn.addEventListener('click', togglePause);
            speedBtns.forEach(btn => btn.addEventListener('click', setSpeed));

            fullscreenBtn.addEventListener('click', toggleFullscreen);
            document.addEventListener('fullscreenchange', () => {
                const isFullscreen = !!document.fullscreenElement;
                fullscreenBtn.querySelector('i').className = isFullscreen ? 'fas fa-compress' : 'fas fa-expand';
                setTimeout(onWindowResize, 100);
            });
            // View controls are now handled via switchMainTab in the navbar
            
            mapZoomInBtn.addEventListener('click', () => changeMapZoom(1.2));
            mapZoomOutBtn.addEventListener('click', () => changeMapZoom(1 / 1.2));
            mapResetBtn.addEventListener('click', resetMap);

            document.getElementById('map-pan-left').addEventListener('click', () => panView('left'));
            document.getElementById('map-pan-right').addEventListener('click', () => panView('right'));
            document.getElementById('map-pan-up').addEventListener('click', () => panView('up'));
            document.getElementById('map-pan-down').addEventListener('click', () => panView('down'));

            // Process Tree zoom controls
            if (pTreeZoomIn) pTreeZoomIn.addEventListener('click', () => { pTreeScale = Math.min(3, pTreeScale + 0.1); updatePTreeZoom(); });
            if (pTreeZoomOut) pTreeZoomOut.addEventListener('click', () => { pTreeScale = Math.max(0.3, pTreeScale - 0.1); updatePTreeZoom(); });
            if (pTreeReset) pTreeReset.addEventListener('click', () => { pTreeScale = 1; updatePTreeZoom(); });
            window.addEventListener('resize', onWindowResize, false);
            initMapInteractions();
            document.addEventListener('keydown', (e) => {
                if (e.key === 'Escape' && body.classList.contains('viz-fullscreen')) {
                    toggleFullscreen();
                }
                // Only toggle pause if the main content is visible
                if (e.key === ' ' && !mainContent.classList.contains('hidden')) {
                    e.preventDefault();
                    togglePause();
                }
            });

            function handleFile(file) {
                if (file && (file.type === 'application/json' || file.name.toLowerCase().endsWith('.json'))) {
                    const reader = new FileReader();
                    reader.onload = (e) => {
                        try {
                            let content = e.target.result;
                            // Clean up Python JSON artifacts commonly found in CAPE reports
                            content = content.replace(/:\s*NaN\b/g, ': null')
                                .replace(/:\s*Infinity\b/g, ': null')
                                .replace(/:\s*-Infinity\b/g, ': null');
                            reportData = JSON.parse(content);
                            startVisualization();
                        } catch (err) {
                            alert('Error parsing JSON.\n' + err.message);
                            console.error(err);
                        }
                    };
                    reader.readAsText(file);
                } else { alert('Please upload a valid JSON file.'); }
            }

            function startVisualization() {
                if (!reportData) return;

                document.getElementById('timeline-container').innerHTML = '';
                document.getElementById('geolocation-container').innerHTML = '<p class="text-gray-400 text-sm empty-state">IP geolocations will appear here as they are discovered during simulation.</p>';
                document.getElementById('process-tree-container').innerHTML = '<p class="text-gray-400 text-sm empty-state">Processes will appear here as they spawn.</p>';
                const regContainer = document.getElementById('registry-container');
                if (regContainer) regContainer.innerHTML = '<p class="text-gray-400 text-sm empty-state">Registry keys modified or created will appear here.</p>';
                cancelAnimationFrame(animationFrameId);

                uploadContainer.classList.add('hidden');
                if (dashboardUi) dashboardUi.classList.remove('hidden');
                switchMainTab('3d');


                isPaused = false;
                playbackSpeed = 1.0;
                simulationTime = 0;
                nextEventIndex = 0;
                animationStarted = false;
                animationEnded = false;
                pendingView = null;
                playPauseBtn.innerHTML = '<i class="fas fa-pause"></i>';
                speedBtns.forEach(btn => btn.classList.toggle('active', btn.dataset.speed === '1.0'));
                geolocationData = {};
                timelineEventsByIP = {};
                // reset persistent connection visuals
                connectionSequence = [];
                // Clear any existing map pins and reset map
                if (leafletMap) {
                    Object.values(mapPins).forEach(p => {
                        if (p && typeof p.remove === 'function') p.remove();
                    });
                    for (const k of Object.keys(mapPins)) delete mapPins[k];

                    if (currentPolyline) {
                        leafletMap.removeLayer(currentPolyline);
                        currentPolyline = null;
                    }
                    leafletMap.setView([20, 0], 2);
                }

                populateMalwareInfo(reportData);
                populateRegistryInfo(reportData);
                populateFilesDropped(reportData);
                populateDnsTable(reportData);
                populateFlowsTable(reportData);
                populateMitreMatrix(reportData);
                populateSignatures(reportData);
                populateStaticAnalysis(reportData);
                populateProcessTreeOrDns(reportData);
                timelineEvents = createTimelineEvents(reportData);
                init3DScene();
                // ensure initial sync of map/globe/3D labels
                syncAllViews();
            }

            function returnToUploadScreen() {
                cancelAnimationFrame(animationFrameId);
                uploadContainer.style.display = 'flex';
                mainContent.classList.add('hidden');
            }

            function calculateThreatScore(data) {
                // Use malscore directly from CAPE report as requested
                let capeScore = 0;
                if (data.malscore !== undefined) {
                    capeScore = parseFloat(data.malscore);
                } else if (data.info && data.info.score !== undefined) {
                    capeScore = parseFloat(data.info.score);
                } else if (data.info && data.info.malscore !== undefined) {
                    capeScore = parseFloat(data.info.malscore);
                }

                return isNaN(capeScore) ? 0 : Math.min(10, Math.max(0, capeScore));
            }

            function getThreatVerdict(score, data) {
                const sigCount = data.signatures?.length || 0;
                const droppedCount = (data.dropped?.length || 0);
                const networkHosts = data.network?.hosts?.length || 0;

                if (score === 0 && sigCount === 0) {
                    return { level: 'safe', icon: 'fa-shield-alt', text: 'Safe to Use - No malicious indicators detected', detail: 'This sample shows no signatures, no suspicious network activity, and no file drops.' };
                } else if (score <= 1) {
                    return { level: 'safe', icon: 'fa-shield-alt', text: 'Safe - Minimal activity detected', detail: 'Very low threat indicators. The sample appears benign.' };
                } else if (score <= 3) {
                    return { level: 'low', icon: 'fa-check-circle', text: 'Low Risk - Minor suspicious behavior', detail: `${sigCount} signature(s) triggered with low severity.` };
                } else if (score <= 6) {
                    return { level: 'moderate', icon: 'fa-exclamation-triangle', text: 'Moderate Risk - Suspicious activity detected', detail: `${sigCount} signature(s), ${networkHosts} network connection(s), ${droppedCount} file(s) dropped.` };
                } else if (score <= 8) {
                    return { level: 'high', icon: 'fa-radiation', text: 'High Threat - Likely malicious', detail: `Significant malicious behavior: ${sigCount} signature(s), ${networkHosts} C2 connection(s), ${droppedCount} payload(s) dropped.` };
                } else {
                    return { level: 'critical', icon: 'fa-skull-crossbones', text: 'Critical Threat - Confirmed malicious', detail: `Severe malicious activity: ${sigCount} signature(s), ${networkHosts} C2 connection(s), ${droppedCount} payload(s) dropped.` };
                }
            }

            async function fetchMalwareBazaarInfo(sha256) {
                if (!sha256) return null;

                // Strategy: Try the server proxy first (bypasses CORS and university firewalls),
                // then fall back to the direct API call if the proxy is unavailable.

                try {
                    const response = await fetch('/api/malware-bazaar', {
                        method: 'POST',
                        headers: {
                            'Content-Type': 'application/json'
                        },
                        body: JSON.stringify({ hash: sha256 })
                    });

                    if (!response.ok) {
                        throw new Error('Proxy request failed with status ' + response.status);
                    }

                    const jsonData = await response.json();
                    if (jsonData.data && jsonData.data.length > 0) {
                        return jsonData.data[0];
                    }
                    return null;
                } catch (proxyError) {
                    console.warn('Server proxy failed, trying direct API call:', proxyError);

                    // Fallback: direct API call
                    try {
                        const formData = new FormData();
                        formData.append('query', 'get_info');
                        formData.append('hash', sha256);

                        const response = await fetch('https://mb-api.abuse.ch/api/v1/', {
                            method: 'POST',
                            headers: {
                                'Auth-Key': 'c142633e2abd97535582df9842fbfbbfcb7298e243d2a4ad'
                            },
                            body: formData
                        });

                        if (!response.ok) {
                            throw new Error('Direct API request failed');
                        }

                        const jsonData = await response.json();
                        if (jsonData.data && jsonData.data.length > 0) {
                            return jsonData.data[0];
                        }
                        return null;
                    } catch (error) {
                        console.warn('Both proxy and direct API calls failed:', error);
                        return null;
                    }
                }
            }

            async function populateMalwareInfo(data) {
                const target = data.target || {};
                const calculatedScore = calculateThreatScore(data);

                // Initial HTML without Malware Bazaar data
                let malwareInfoHTML = `
                    <p><strong class="text-gray-300">File Name:</strong> <span class="text-indigo-400 break-all">${target.file?.name || 'N/A'}</span></p>
                    <p><strong class="text-gray-300">MD5:</strong> <span class="font-mono text-sm">${target.file?.md5 || 'N/A'}</span></p>
                    <p><strong class="text-gray-300">SHA256:</strong> <span class="font-mono text-sm break-all">${target.file?.sha256 || 'N/A'}</span></p>`;

                document.getElementById('malware-info').innerHTML = malwareInfoHTML + '<p class="text-gray-400 text-xs mt-2"><i class="fas fa-spinner fa-spin mr-1"></i>Fetching Malware Bazaar data...</p>';

                const scoreLabel = document.getElementById('threat-score-label');
                const scoreBar = document.getElementById('threat-bar-inner');
                const verdictEl = document.getElementById('threat-verdict');
                scoreLabel.textContent = calculatedScore.toFixed(2);
                scoreBar.style.width = `${Math.max(calculatedScore * 10, calculatedScore === 0 ? 3 : 0)}%`;
                if (calculatedScore > 7) {
                    scoreLabel.className = 'font-bold text-4xl text-red-500 transition-colors';
                    scoreBar.style.backgroundColor = '#ef4444';
                } else if (calculatedScore > 4) {
                    scoreLabel.className = 'font-bold text-4xl text-yellow-400 transition-colors';
                    scoreBar.style.backgroundColor = '#f59e0b';
                } else {
                    scoreLabel.className = 'font-bold text-4xl text-green-400 transition-colors';
                    scoreBar.style.backgroundColor = '#10b981';
                }

                // Show verdict badge
                const verdict = getThreatVerdict(calculatedScore, data);
                verdictEl.className = `threat-verdict ${verdict.level}`;
                verdictEl.innerHTML = `<i class="fas ${verdict.icon}"></i><div><div>${verdict.text}</div><div style="font-weight:400; font-size:0.7rem; opacity:0.8; margin-top:2px;">${verdict.detail}</div></div>`;
                verdictEl.style.display = 'flex';

                // Fetch Malware Bazaar data
                const mbData = await fetchMalwareBazaarInfo(target.file?.sha256);
                if (mbData) {
                    malwareInfoHTML += `
                    <p><strong class="text-gray-300">Malware Family:</strong> <span class="text-indigo-400">${mbData.signature || 'Not Known'}</span></p>
                    <p><strong class="text-gray-300">First Seen:</strong> <span class="text-indigo-400">${mbData.first_seen || 'Not Known'}</span></p>
                    <p><strong class="text-gray-300">Last Seen:</strong> <span class="text-indigo-400">${mbData.last_seen || 'Not Known'}</span></p>`;
                } else {
                    malwareInfoHTML += '<p class="text-gray-400 text-xs mt-2">Malware Bazaar data not available</p>';
                }

                document.getElementById('malware-info').innerHTML = malwareInfoHTML;
            }

            function populateRegistryInfo(data) {
                const container = document.getElementById('registry-container');
                if (!container) return;

                const written = data.behavior?.summary?.keys_written || [];
                const deleted = data.behavior?.summary?.keys_deleted || [];

                let allKeys = [];
                written.forEach(k => allKeys.push({ key: k, type: 'Written', color: 'text-yellow-400', icon: 'fa-pen' }));
                deleted.forEach(k => allKeys.push({ key: k, type: 'Deleted', color: 'text-red-400', icon: 'fa-trash' }));

                // If keys_written/deleted are missing, try extracting from process API calls
                if (allKeys.length === 0 && data.behavior?.processes) {
                    data.behavior.processes.forEach(p => {
                        if (p.calls) {
                            p.calls.forEach(c => {
                                if (c.category === 'registry' && (c.api.includes('SetValue') || c.api.includes('CreateKey') || c.api.includes('DeleteKey'))) {
                                    let keyName = 'Unknown Key';
                                    if (Array.isArray(c.arguments)) {
                                        // Priority: try known named fields first
                                        const fieldNames = ['FullName', 'KeyName', 'Registry', 'Handle', 'ObjectName'];
                                        const subFields = ['SubKey', 'ValueName', 'Value'];
                                        let root = null, sub = null;
                                        for (const fn of fieldNames) { root = c.arguments.find(a => a.name === fn); if (root) break; }
                                        for (const sf of subFields) { sub = c.arguments.find(a => a.name === sf); if (sub) break; }

                                        let parts = [];
                                        if (root) parts.push(root.pretty_value || root.value || '');
                                        if (sub) parts.push(sub.pretty_value || sub.value || '');

                                        if (parts.some(p => p)) {
                                            keyName = parts.filter(Boolean).join('\\').replace(/\\\\/g, '\\');
                                        } else {
                                            // Scan all args for anything that looks like a registry path
                                            const regArg = c.arguments.find(a => {
                                                const v = String(a.pretty_value || a.value || '');
                                                return v.startsWith('HKEY_') || v.startsWith('HKLM') || v.startsWith('HKCU') || v.includes('\\SOFTWARE\\') || v.includes('\\SYSTEM\\');
                                            });
                                            keyName = regArg ? (regArg.pretty_value || regArg.value) : `${c.api}(${c.arguments.map(a => a.name).join(', ')})`;
                                        }
                                    } else if (c.arguments) {
                                        keyName = c.arguments.regkey || c.arguments.key_handle || c.arguments.key_name || c.arguments.FullName || c.arguments.KeyName || `${c.api} call`;
                                    }
                                    let type = c.api.includes('Delete') ? 'Deleted' : (c.api.includes('Create') ? 'Created' : 'Written');
                                    let color = type === 'Deleted' ? 'text-red-400' : (type === 'Created' ? 'text-green-400' : 'text-yellow-400');
                                    let icon = type === 'Deleted' ? 'fa-trash' : (type === 'Created' ? 'fa-plus' : 'fa-pen');

                                    if (!allKeys.some(k => k.key === keyName)) {
                                        allKeys.push({ key: keyName, type, color, icon });
                                    }
                                }
                            });
                        }
                    });
                }

                if (allKeys.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state">No significant registry modifications detected.</p>';
                    return;
                }

                let html = '<ul class="space-y-2">';
                allKeys.slice(0, 50).forEach(item => { // Limit to 50 for performance and UI brevity
                    html += `
                    <li class="bg-gray-800 rounded p-2 border border-gray-700 break-all text-xs">
                        <div class="flex items-center mb-1">
                            <i class="fas ${item.icon} ${item.color} mr-2"></i>
                            <span class="font-semibold ${item.color}">${item.type}</span>
                        </div>
                        <div class="text-gray-300 font-mono ml-5">${item.key}</div>
                    </li>`;
                });
                if (allKeys.length > 50) {
                    html += `<li class="text-center text-gray-500 text-xs py-2">+ ${allKeys.length - 50} more registry operations hidden</li>`;
                }
                html += '</ul>';
                container.innerHTML = html;
            }

            window.switchMainTab = function (tab) {
                const tabs = ['3d', 'map', 'tree', 'behavior', 'registry', 'files', 'dns', 'flows', 'mitre', 'signatures', 'static'];
                const panels = {
                    '3d': 'visualization-3d-container',
                    'map': 'geolocation-map-container',
                    'tree': 'process-tree-container',
                    'behavior': 'behavior-summary-container',
                    'registry': 'registry-container',
                    'files': 'files-dropped-container',
                    'dns': 'dns-table-container',
                    'flows': 'flows-table-container',
                    'mitre': 'mitre-container',
                    'signatures': 'signatures-container',
                    'static': 'static-info-container'
                };

                tabs.forEach(t => {
                    const panel = document.getElementById(panels[t]);
                    const tabBtn = document.getElementById(`nav-tab-${t}`);
                    if (t === tab) {
                        if (panel) panel.classList.remove('hidden');
                        if (tabBtn) tabBtn.classList.add('active');
                        
                        // Populate data if needed
                        if (tab === 'behavior') populateBehavioralSummary(reportData);
                        if (tab === 'dns') populateDnsTable(reportData);
                        if (tab === 'flows') populateFlowsTable(reportData);
                        if (tab === 'mitre') populateMitreMatrix(reportData);
                        if (tab === 'signatures') populateSignatures(reportData);
                        if (tab === 'static') populateStaticAnalysis(reportData);
                        if (tab === 'registry') populateRegistryActivity(reportData);
                        if (tab === 'files') populateFilesDropped(reportData);
                    } else {
                        if (panel) panel.classList.add('hidden');
                        if (tabBtn) tabBtn.classList.remove('active');
                    }
                });

                // Context-aware controls visibility
                const playbackControls = document.getElementById('playback-controls');
                const geoPanel = document.getElementById('geolocation-panel');

                if (playbackControls) playbackControls.style.display = (tab === '3d' || tab === 'map') ? 'flex' : 'none';
                if (geoPanel) geoPanel.style.display = (tab === '3d' || tab === 'map') ? 'block' : 'none';

                // Handle Floating Nav visibility
                const floatingNav = document.getElementById('vis-floating-nav');
                if (floatingNav) floatingNav.classList.toggle('hidden', !(tab === '3d' || tab === 'map'));
                
                // Handle Map specific logic
                if (tab === 'map' && reportData) {
                    if (!leafletMap) {
                        setTimeout(initLeafletMap, 100);
                    } else {
                        setTimeout(() => leafletMap.invalidateSize(), 200);
                    }
                }
            };

            window.switchRegTab = (tab) => switchMainTab(tab === 'files' ? 'files' : 'registry');
            window.switchPtTab = (tab) => switchMainTab(tab);

            window.jumpToSignature = function (index) {
                window.forensicNavigationSource = 'mitre';
                switchMainTab('signatures');
                setTimeout(() => {
                    const card = document.getElementById(`sig-card-${index}`);
                    if (card) {
                        card.scrollIntoView({ behavior: 'smooth', block: 'center' });
                        // Add a temporary highlight effect
                        card.classList.add('ring-2', 'ring-white', 'ring-offset-4', 'ring-offset-gray-900');
                        setTimeout(() => card.classList.remove('ring-2', 'ring-white', 'ring-offset-4', 'ring-offset-gray-900'), 2000);
                        
                        // Expand the details
                        showSignatureDetails(index);
                    }
                }, 200);
            };

            function populateBehavioralSummary(data) {
                const container = document.getElementById('behavior-summary-container');
                if (!container) return;
                const behavior = data.behavior || {};
                const summary = behavior.summary || {};

                const sections = [
                    { title: 'Executed Command Lines', key: 'executed_commands', icon: 'fa-terminal', color: 'text-indigo-400' },
                    { title: 'System Mutexes', key: 'mutexes', icon: 'fa-lock', color: 'text-emerald-400' },
                    { title: 'Services Created/Modified', key: 'created_services', icon: 'fa-user-shield', color: 'text-blue-400' },
                    { title: 'Started Services', key: 'started_services', icon: 'fa-play', color: 'text-emerald-400' }
                ];

                let html = '<div class="space-y-6">';
                
                // Add Unique "Extracted Payloads" section from CAPE data
                const payloads = data.CAPE?.payloads || [];
                if (payloads.length > 0) {
                    html += `
                        <div class="bg-indigo-900/10 p-5 rounded-xl border border-indigo-500/30 shadow-[0_0_20px_rgba(99,102,241,0.1)]">
                            <h4 class="text-indigo-400 font-black text-xs uppercase tracking-[0.25em] mb-4 flex items-center gap-3">
                                <i class="fas fa-box-open"></i> Extracted Payloads / Unpacked Binaries (${payloads.length})
                                <span class="ml-auto text-[8px] bg-indigo-500/20 px-2 py-0.5 rounded text-indigo-300 animate-pulse">Click card to Magnify</span>
                            </h4>
                            <div class="space-y-4">
                                ${payloads.map(p => {
                                    const cardHtml = `
                                    <div class="p-6 bg-black/50 rounded-xl border border-white/10 hover:border-indigo-500/60 transition-all shadow-lg mb-4 cursor-zoom-in group/zoom" 
                                         onclick="zoomForensicCard(this.outerHTML)">
                                        <div class="flex justify-between items-start mb-4 border-b border-white/5 pb-3">
                                            <div class="text-indigo-400 font-black text-sm break-all pr-4 uppercase tracking-tight">${p.name}</div>
                                            <span class="bg-indigo-600 text-white px-3 py-1 rounded-full text-[10px] font-black uppercase shadow-[0_0_10px_rgba(79,70,229,0.4)] flex-shrink-0">Extracted Payload</span>
                                        </div>
                                        <div class="grid grid-cols-2 gap-x-8 gap-y-4 mt-2">
                                            <div class="flex flex-col">
                                                <span class="text-indigo-500/80 font-black text-[10px] uppercase tracking-widest mb-1">Size</span> 
                                                <span class="text-white font-bold text-base">${p.size} <span class="text-gray-500 text-xs font-normal">bytes</span></span>
                                            </div>
                                            <div class="flex flex-col">
                                                <span class="text-indigo-500/80 font-black text-[10px] uppercase tracking-widest mb-1">Type</span> 
                                                <span class="text-white font-bold text-sm">${p.type || 'Data Binary'}</span>
                                            </div>
                                            <div class="flex flex-col col-span-2 bg-indigo-500/5 p-4 rounded-xl border border-indigo-500/30 shadow-inner group/path">
                                                <span class="text-indigo-400 font-black text-[10px] uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                                                    <i class="fas fa-microchip text-indigo-400"></i> Guest Execution Path
                                                </span> 
                                                <span class="text-white font-mono text-xs break-all leading-relaxed bg-black/40 p-2 rounded border border-white/5 group-hover/path:border-indigo-500/40 transition-colors">${p.guest_paths || 'In-Memory Reconstruction Only'}</span>
                                            </div>
                                            <div class="flex flex-col col-span-2 bg-purple-500/5 p-4 rounded-xl border border-purple-500/30 shadow-inner group/ssdeep">
                                                <span class="text-purple-400 font-black text-[10px] uppercase tracking-[0.2em] mb-2 flex items-center gap-2">
                                                    <i class="fas fa-fingerprint text-purple-400"></i> SSDEEP (Fuzzy Hash)
                                                </span> 
                                                <span class="text-gray-100 font-mono text-[10px] break-all leading-tight bg-black/40 p-2 rounded border border-white/5 group-hover/ssdeep:border-purple-500/40 transition-colors">${p.ssdeep || 'N/A'}</span>
                                            </div>
                                        </div>
                                    </div>
                                    `;
                                    return cardHtml;
                                }).join('')}
                            </div>
                            <div class="mt-4 p-3 bg-indigo-500/5 rounded border border-indigo-500/20 text-[10px] text-indigo-300/60 leading-relaxed italic">
                                <i class="fas fa-info-circle mr-1"></i> These payloads were reconstructed from memory or temporary drops during analysis. They often represent the final, decrypted stage of the malware.
                            </div>
                        </div>
                    `;
                }

                sections.forEach(sec => {
                    const items = summary[sec.key] || [];
                    if (items.length > 0) {
                        const displayItems = sec.limit ? items.slice(0, sec.limit) : items;
                        html += `
                            <div class="bg-gray-800/20 p-5 rounded-xl border border-gray-700/50">
                                <h4 class="${sec.color} font-black text-xs uppercase tracking-[0.2em] mb-4 flex items-center gap-3">
                                    <i class="fas ${sec.icon}"></i> ${sec.title} (${items.length})
                                    <span class="ml-auto text-[8px] opacity-40 px-2 py-0.5 rounded animate-pulse">Click to Magnify</span>
                                </h4>
                                <div class="space-y-3 max-h-[400px] overflow-y-auto pr-3 custom-scrollbar">
                                    ${displayItems.map(item => `
                                        <div class="text-xs font-mono font-bold p-4 bg-black/60 rounded-lg border border-white/10 break-all text-white hover:border-${sec.color.split('-')[1]}-500/50 transition-all shadow-inner cursor-zoom-in"
                                             onclick="zoomForensicCard(this.outerHTML)">
                                            ${typeof item === 'object' ? JSON.stringify(item) : item}
                                        </div>
                                    `).join('')}
                                    ${items.length > (sec.limit || Infinity) ? `<div class="text-center text-gray-500 text-xs mt-3 font-bold uppercase tracking-tighter italic">Showing first ${sec.limit} artifacts...</div>` : ''}
                                </div>
                            </div>
                        `;
                    }
                });
                
                if (html === '<div class="space-y-6">') {
                    html += '<p class="text-gray-500 text-sm text-center py-20 italic">No significant behavioral artifacts extracted.</p>';
                }
                html += '</div>';
                container.innerHTML = html;
            }

            function populateDnsTable(data) {
                const container = document.getElementById('dns-table-container');
                if (!container) return;

                const dnsEntries = data.network?.dns || [];
                if (dnsEntries.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state">No DNS queries recorded for this sample.</p>';
                    return;
                }

                let html = `<table class="w-full text-xs border-collapse">
                    <thead>
                        <tr class="border-b border-gray-700">
                            <th class="text-left py-2 px-3 text-gray-400 font-semibold w-8">#</th>
                            <th class="text-left py-2 px-3 text-gray-400 font-semibold">Domain Queried</th>
                            <th class="text-left py-2 px-3 text-gray-400 font-semibold">Type</th>
                            <th class="text-left py-2 px-3 text-gray-400 font-semibold">Response(s)</th>
                        </tr>
                    </thead>
                    <tbody>`;

                dnsEntries.forEach((d, i) => {
                    const answers = Array.isArray(d.answers)
                        ? d.answers.map(a => a.data || a.address || String(a)).filter(Boolean).join(', ')
                        : (d.response || '-');
                    const type = d.type || 'A';
                    const rowBg = i % 2 === 0 ? '' : 'bg-gray-850';
                    html += `<tr class="border-b border-gray-800 hover:bg-gray-800 transition-colors ${rowBg}">
                        <td class="py-2 px-3 text-gray-600 select-none">${i + 1}</td>
                        <td class="py-2 px-3 text-blue-300 font-mono break-all">${d.request || '-'}</td>
                        <td class="py-2 px-3"><span class="bg-indigo-900 text-indigo-300 px-2 py-0.5 rounded text-xs font-mono">${type}</span></td>
                        <td class="py-2 px-3 text-gray-400 font-mono break-all">${answers || '-'}</td>
                    </tr>`;
                });

                html += `</tbody></table>`;
                if (dnsEntries.length > 0) {
                    html = `<p class="text-gray-500 text-xs mb-3">${dnsEntries.length} DNS quer${dnsEntries.length === 1 ? 'y' : 'ies'} recorded</p>` + html;
                }
                container.innerHTML = html;
            }

            function populateFlowsTable(data) {
                const container = document.getElementById('flows-table-container');
                if (!container) return;
                const flows = (data.network?.tcp || []).concat(data.network?.udp || []);
                if (flows.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state">No network flows recorded.</p>';
                    return;
                }
                let html = '<table class="analysis-table"><thead><tr><th>Time</th><th>Protocol</th><th>Source IP</th><th>Dest IP</th><th>Port</th></tr></thead><tbody>';
                flows.sort((a, b) => (a.time || 0) - (b.time || 0)).forEach(f => {
                    const isTcp = data.network?.tcp?.some(tf => tf === f);
                    const proto = isTcp ? 'TCP' : 'UDP';
                    html += `<tr><td>${(f.time || 0).toFixed(3)}s</td><td><span class="px-2 py-0.5 rounded ${isTcp ? 'bg-indigo-900 text-indigo-300' : 'bg-emerald-900 text-emerald-300'} text-[10px]">${proto}</span></td><td>${f.src}</td><td>${f.dst}</td><td class="text-indigo-400 font-bold">${f.dport || '-'}</td></tr>`;
                });
                html += '</tbody></table>';
                container.innerHTML = html;
            }

            function populateMitreMatrix(data) {
                const container = document.getElementById('mitre-container');
                if (!container) return;
                const ttps = data.ttps || [];
                const signatures = data.signatures || [];

                if (ttps.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state italic py-20 text-center">No MITRE ATT&CK techniques mapped for this sample.</p>';
                    return;
                }

                // Group by tactic
                const tactics = {};
                ttps.forEach(t => {
                    const sig = signatures.find(s => s.name === t.signature);
                    const tacticName = sig?.categories?.[0] || 'General';
                    if (!tactics[tacticName]) tactics[tacticName] = [];
                    tactics[tacticName].push(t);
                });

                let html = `
                    <div class="mb-6 bg-indigo-500/5 p-4 rounded-lg border border-indigo-500/20 text-xs text-indigo-300/80 flex items-center gap-3">
                        <i class="fas fa-mouse-pointer animate-bounce"></i>
                        <span>Click any technique card below to drill down into the specific signatures and forensic triggers.</span>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4" id="mitre-grid-root">
                `;

                for (const [tactic, techniques] of Object.entries(tactics)) {
                    html += `
                        <div class="space-y-3">
                            <h4 class="text-gray-500 font-black text-[10px] uppercase tracking-[0.2em] mb-4 border-b border-gray-800 pb-2 flex items-center justify-between">
                                <span>${tactic.replace(/_/g, ' ')}</span>
                                <span class="bg-gray-800 px-2 rounded text-gray-600">${techniques.length}</span>
                            </h4>
                            <div class="space-y-2">
                                ${techniques.map(t => {
                                    const sigId = t.ttps?.[0] || 'T-Unknown';
                                    const sig = signatures.find(s => s.name === t.signature);
                                    const sevClass = (sig && sig.severity >= 3) ? 'border-red-500/40 bg-red-500/5 hover:bg-red-500/10' : 'border-indigo-500/20 bg-indigo-500/5 hover:bg-indigo-500/10';
                                    const iconColor = (sig && sig.severity >= 3) ? 'text-red-400' : 'text-indigo-400';
                                    
                                    return `
                                        <div class="mitre-technique group p-3 rounded-lg border ${sevClass} cursor-pointer transition-all hover:scale-[1.02] active:scale-95" 
                                             onclick="showMitreDetails('${sigId}', '${(t.signature || 'Unknown').replace(/'/g, "\\'")}', '${tactic.replace(/'/g, "\\'")}')">
                                            <div class="flex justify-between items-start mb-1">
                                                <span class="text-[10px] font-black ${iconColor} tracking-tighter">${sigId}</span>
                                                <i class="fas fa-chevron-right text-[8px] text-gray-700 group-hover:text-white transition-colors"></i>
                                            </div>
                                            <div class="text-white font-bold text-xs leading-snug pr-4">${t.signature || 'Unknown'}</div>
                                        </div>
                                    `;
                                }).join('')}
                            </div>
                        </div>
                    `;
                }
                html += '</div>';
                
                // Details Panel (hidden by default)
                html += `
                    <div id="mitre-drilldown-panel" class="hidden mt-8 pt-8 border-t border-gray-800">
                        <div class="flex justify-between items-center mb-6">
                            <div class="flex flex-col">
                                <h3 id="mitre-drilldown-title" class="text-white font-black text-xl tracking-tight leading-none mb-1">Technique Details</h3>
                                <span id="mitre-drilldown-subtitle" class="text-indigo-400 font-bold text-xs uppercase tracking-widest">Tactic Name</span>
                            </div>
                            <button onclick="hideMitreDetails()" class="bg-gray-800 hover:bg-gray-700 text-gray-400 hover:text-white px-4 py-2 rounded-lg text-xs font-bold transition-all flex items-center gap-2">
                                <i class="fas fa-th"></i> Back to Grid
                            </button>
                        </div>
                        <div id="mitre-drilldown-content" class="grid grid-cols-1 gap-4"></div>
                    </div>
                `;

                container.innerHTML = html;

                window.showMitreDetails = function(id, technique, tactic) {
                    const grid = document.getElementById('mitre-grid-root');
                    const panel = document.getElementById('mitre-drilldown-panel');
                    const title = document.getElementById('mitre-drilldown-title');
                    const subtitle = document.getElementById('mitre-drilldown-subtitle');
                    const content = document.getElementById('mitre-drilldown-content');

                    title.innerText = technique.replace(/_/g, ' ');
                    subtitle.innerText = `${tactic.replace(/_/g, ' ')} | ${id}`;
                    
                    const matchingSigs = signatures.filter(s => s.name === technique || (s.ttps && s.ttps.some(tt => tt.id === id)));
                    
                    let sigHtml = '';
                    if (matchingSigs.length > 0) {
                        sigHtml = matchingSigs.map(s => {
                            const sevCol = s.severity >= 3 ? 'text-red-400' : (s.severity === 2 ? 'text-orange-400' : 'text-emerald-400');
                            const sevBg = s.severity >= 3 ? 'bg-red-500/10 border-red-500/30' : (s.severity === 2 ? 'bg-orange-500/10 border-orange-500/30' : 'bg-emerald-500/10 border-emerald-500/30');
                            return `
                                <div class="${sevBg} p-6 rounded-xl border flex flex-col gap-4 shadow-xl">
                                    <div class="flex justify-between items-start">
                                        <div class="flex flex-col">
                                            <span class="text-[10px] text-gray-500 uppercase font-black tracking-widest mb-1">Triggering Signature</span>
                                            <h5 class="text-white font-bold text-lg leading-tight">${s.description}</h5>
                                        </div>
                                        <div class="${sevCol} font-black text-sm px-3 py-1 bg-black/40 rounded border border-white/5">SEVERITY: ${s.severity}</div>
                                    </div>
                                    <div class="text-gray-400 text-sm leading-relaxed italic bg-black/30 p-4 rounded-lg border border-white/5">
                                        <i class="fas fa-quote-left mr-3 text-gray-600 text-lg"></i>
                                        The malware exhibited behavioral patterns associated with <strong>${technique.replace(/_/g, ' ')}</strong>. This is a common tactic for persistence or data exfiltration.
                                    </div>
                                    <button class="w-full py-3 bg-white/5 hover:bg-white/10 rounded-xl text-xs font-black uppercase tracking-[0.2em] text-gray-300 transition-all border border-white/5"
                                            onclick="jumpToSignature(${s.originalIndex || signatures.indexOf(s)})">
                                        Analyze Detailed Forensic Evidence <i class="fas fa-external-link-alt ml-2 text-[10px]"></i>
                                    </button>
                                </div>
                            `;
                        }).join('');
                    } else {
                        sigHtml = `<div class="py-20 text-center text-gray-600 italic border border-dashed border-gray-800 rounded-xl">No specific signature evidence mapped to this technique.</div>`;
                    }

                    content.innerHTML = sigHtml;
                    grid.classList.add('hidden');
                    panel.classList.remove('hidden');
                    panel.scrollIntoView({ behavior: 'smooth' });
                };

                window.hideMitreDetails = function() {
                    const grid = document.getElementById('mitre-grid-root');
                    const panel = document.getElementById('mitre-drilldown-panel');
                    grid.classList.remove('hidden');
                    panel.classList.add('hidden');
                };
            }

            function populateSignatures(data) {
                const container = document.getElementById('signatures-container');
                if (!container) return;
                const sigs = data.signatures || [];
                if (sigs.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state">No signatures triggered.</p>';
                    return;
                }

                // IMPORTANT: We need to keep original index for the click handler
                const sigsWithMeta = sigs.map((s, i) => ({ ...s, originalIndex: i }));
                sigsWithMeta.sort((a, b) => (b.severity || 0) - (a.severity || 0));

                let html = '<div class="space-y-4">';
                sigsWithMeta.forEach((s) => {
                    const sevClass = (s.severity || 0) >= 3 ? 'sig-sev-high' : ((s.severity || 0) >= 2 ? 'sig-sev-medium' : 'sig-sev-low');
                    const sevColor = (s.severity || 0) >= 3 ? 'text-red-400' : ((s.severity || 0) >= 2 ? 'text-orange-400' : 'text-emerald-400');
                    html += `
                        <div id="sig-card-${s.originalIndex}" class="sig-badge ${sevClass}" onclick="showSignatureDetails(${s.originalIndex})">
                            <div class="flex-grow">
                                <div class="flex justify-between items-center mb-1">
                                    <span class="font-bold text-white">${s.name}</span>
                                    <span class="${sevColor} text-[10px] font-bold uppercase">Severity: ${s.severity || 0}</span>
                                </div>
                                <p class="text-gray-400 text-xs leading-relaxed">${s.description || 'No description available.'}</p>
                                <div class="mt-2 text-[10px] text-gray-500 italic">Click to expand forensic evidence...</div>
                            </div>
                        </div>
                    `;
                });
                html += '</div>';
                container.innerHTML = html;
            }

            window.showSignatureDetails = function (index) {
                try {
                    const sig = reportData.signatures[index];
                    if (!sig) return;

                    const title = document.getElementById('proc-details-title');
                    const subtitle = document.getElementById('proc-details-subtitle');
                    const content = document.getElementById('proc-details-content');
                    const icon = document.getElementById('proc-details-icon');

                    if (!title || !content) return;

                    title.innerText = sig.name || 'Analysis Signature';
                    subtitle.innerText = `Forensic Evidence - Confidence: ${sig.confidence || 0}%`;
                    icon.className = 'fas fa-shield-alt text-orange-400 text-xl';

                    let marksHtml = `<p class="text-gray-400 text-xs mb-4 leading-relaxed">${sig.description || 'No description available.'}</p>`;

                    // Support all known forensic schemas: .data, .marks, and the modern .new_data/.signs
                    let evidence = [];
                    if (sig.data && sig.data.length > 0) evidence = evidence.concat(sig.data);
                    if (sig.marks && sig.marks.length > 0) evidence = evidence.concat(sig.marks);
                    if (sig.new_data && sig.new_data.length > 0) {
                        sig.new_data.forEach(item => {
                            const proc = item.process || {};
                            if (item.signs && item.signs.length > 0) {
                                item.signs.forEach(s => {
                                    evidence.push({ ...s, process_context: proc });
                                });
                            }
                        });
                    }

                    if (evidence.length > 0) {
                        const groups = {};
                        evidence.forEach(m => {
                            const rawType = m.type || (m.category ? m.category : 'DETECTION');
                            const mType = rawType.toUpperCase();
                            if (!groups[mType]) groups[mType] = [];
                            groups[mType].push(m);
                        });

                        marksHtml += '<div class="space-y-4 mt-6">';
                        Object.entries(groups).forEach(([type, items], gIdx) => {
                            const groupId = `ev-group-${gIdx}`;
                            const icon = type.includes('CALL') ? 'fa-terminal' : (type.includes('FILE') ? 'fa-file-alt' : (type.includes('REG') ? 'fa-edit' : 'fa-fingerprint'));
                            const color = type.includes('CALL') ? 'text-indigo-400' : (type.includes('DETECTION') ? 'text-orange-400' : 'text-emerald-400');
                            const border = type.includes('CALL') ? 'border-indigo-500/50' : (type.includes('DETECTION') ? 'border-orange-500/50' : 'border-emerald-500/50');
                            const grad = type.includes('CALL') ? 'ev-header-gradient-indigo' : (type.includes('DETECTION') ? 'ev-header-gradient-orange' : 'ev-header-gradient-emerald');
                            const glow = type.includes('CALL') ? 'glow-indigo' : (type.includes('DETECTION') ? 'glow-orange' : 'glow-emerald');
                            
                            marksHtml += `
                                <div class="rounded-xl border ${border} ${glow} overflow-hidden transition-all duration-300">
                                    <div class="flex items-center justify-between p-5 ${grad} cursor-pointer hover:brightness-125 transition-all" onclick="toggleEvGroup('${groupId}')">
                                        <div class="flex items-center gap-4">
                                            <div class="w-10 h-10 rounded-lg bg-black/40 flex items-center justify-center border border-white/10">
                                                <i class="fas ${icon} ${color} text-lg"></i>
                                            </div>
                                            <div class="${color} font-black text-xs uppercase tracking-[0.25em]">
                                                ${type} <span class="ml-3 px-3 py-1 bg-black/60 rounded text-white font-mono text-sm">${items.length}</span>
                                            </div>
                                        </div>
                                        <i class="fas fa-chevron-down text-gray-500 text-sm transition-transform duration-300" id="${groupId}-chevron"></i>
                                    </div>
                                    <div class="p-5 space-y-4 hidden bg-gray-900/60 backdrop-blur-md" id="${groupId}">
                                        ${items.map(m => {
                                            const procInfo = m.process_context ? `<div class="text-xs text-indigo-300/80 mb-3 flex items-center gap-2 font-bold"><i class="fas fa-microchip"></i> ${m.process_context.process_name || ''} <span class="text-gray-600">|</span> PID: ${m.process_context.process_id || ''}</div>` : '';
                                            const borderCol = type.includes('CALL') ? 'border-indigo-500/50' : (type.includes('DETECTION') ? 'border-orange-500/50' : 'border-emerald-500/50');
                                            return `
                                                <div class="mark-item ${borderCol} p-4">
                                                    ${procInfo}
                                                    <div class="text-gray-300 text-xs font-mono space-y-2">
                                                        ${Object.entries(m).map(([k, v]) => {
                                                            if (k === 'type' || k === 'category' || k === 'process_context') return '';
                                                            const valStr = typeof v === 'object' ? JSON.stringify(v) : String(v);
                                                            return `<div class="flex gap-4 items-baseline"><span class="text-gray-500 font-bold w-24 flex-shrink-0 uppercase text-[10px] tracking-tighter">${k}:</span> <span class="break-all text-gray-100">${valStr}</span></div>`;
                                                        }).join('')}
                                                    </div>
                                                </div>
                                            `;
                                        }).join('')}
                                    </div>
                                </div>
                            `;
                        });
                        marksHtml += '</div>';
                        
                        // Add the toggle script if not present
                        if (!window.toggleEvGroup) {
                            window.toggleEvGroup = function(id) {
                                const el = document.getElementById(id);
                                const chev = document.getElementById(id + '-chevron');
                                if (el.classList.contains('hidden')) {
                                    el.classList.remove('hidden');
                                    chev.style.transform = 'rotate(180deg)';
                                } else {
                                    el.classList.add('hidden');
                                    chev.style.transform = 'rotate(0deg)';
                                }
                            };
                        }
                    } else {
                        marksHtml += `
                            <div class="flex flex-col items-center justify-center py-8 bg-gray-800/20 rounded-lg border border-dashed border-gray-700 mt-4">
                                <i class="fas fa-search text-gray-600 text-2xl mb-2"></i>
                                <div class="text-gray-500 text-xs italic">No specific forensic marks recorded for this signature.</div>
                            </div>`;
                    }

                    content.innerHTML = marksHtml;
                    document.getElementById('proc-details-modal').classList.remove('hidden');
                } catch (err) {
                    console.error("Signature Detail Error:", err);
                }
            };

            function populateStaticAnalysis(data) {
                const container = document.getElementById('static-info-container');
                if (!container) return;

                const file = data.target?.file || {};
                const pe = file.pe || {};
                const strings = (file.strings || []).slice(0, 500);

                // Handle both Array and Object schemas for PE Imports
                let importsArr = [];
                if (Array.isArray(pe.imports)) {
                    importsArr = pe.imports;
                } else if (pe.imports && typeof pe.imports === 'object') {
                    importsArr = Object.keys(pe.imports).map(dll => ({ dll, functions: pe.imports[dll] }));
                }

                let html = `
                    <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                        <!-- Card 1: File Identity -->
                        <div class="bg-gray-800/30 p-5 rounded-lg border border-gray-700">
                            <h4 class="text-indigo-400 font-bold mb-4 flex items-center gap-2 text-sm uppercase tracking-wider"><i class="fas fa-file"></i> File Identity</h4>
                            <div class="space-y-4 text-sm">
                                <div class="flex justify-between"><span class="text-gray-400">Name:</span> <span class="text-gray-300 font-mono font-bold">${file.name || '-'}</span></div>
                                <div class="flex justify-between"><span class="text-gray-400">Size:</span> <span class="text-gray-300 font-bold">${(file.size / 1024).toFixed(2)} KB</span></div>
                                <div class="flex justify-between"><span class="text-gray-400">Type:</span> <span class="text-gray-300">${file.type || '-'}</span></div>
                                <div class="mt-6 pt-6 border-t border-gray-700 space-y-3">
                                    <div class="mb-3"><span class="text-gray-500 text-xs uppercase tracking-tighter">MD5:</span> <div class="text-gray-400 font-mono break-all mt-1 bg-black/20 p-2 rounded">${file.md5 || '-'}</div></div>
                                    <div class="mb-3"><span class="text-gray-500 text-xs uppercase tracking-tighter">SHA1:</span> <div class="text-gray-400 font-mono break-all mt-1 bg-black/20 p-2 rounded">${file.sha1 || '-'}</div></div>
                                    <div class="mb-3"><span class="text-gray-500 text-xs uppercase tracking-tighter">SHA256:</span> <div class="text-gray-400 font-mono break-all mt-1 bg-black/20 p-2 rounded">${file.sha256 || '-'}</div></div>
                                </div>
                            </div>
                        </div>

                        <!-- Card 2: PE Imports -->
                        <div class="bg-gray-800/30 p-6 rounded-lg border border-gray-700">
                            <h4 class="text-blue-400 font-bold mb-4 flex items-center gap-2 text-sm uppercase tracking-wider"><i class="fas fa-code"></i> PE Imports (${importsArr.length})</h4>
                            <div class="flex flex-wrap gap-2.5 max-h-[350px] overflow-y-auto pr-2 custom-scrollbar">
                                ${importsArr.map(i => `<span class="bg-blue-500/10 text-blue-300 px-3 py-1.5 rounded text-xs border border-blue-500/30 font-medium">${i.dll || i}</span>`).join('')}
                                ${importsArr.length === 0 ? '<div class="italic text-gray-600 text-sm py-10">No PE imports identified.</div>' : ''}
                            </div>
                        </div>

                        <!-- Card 3: Summary Statistics -->
                        <div class="bg-gray-800/30 p-6 rounded-lg border border-gray-700">
                            <h4 class="text-emerald-400 font-bold mb-4 flex items-center gap-2 text-sm uppercase tracking-wider"><i class="fas fa-chart-line"></i> Summary Statistics</h4>
                            <div class="space-y-6 text-sm">
                                <div class="flex justify-between items-center bg-gray-900/50 p-4 rounded-xl border border-white/5">
                                    <span class="text-gray-400 font-medium">Total Processes</span>
                                    <span class="text-white font-black text-2xl">${data.behavior?.processes?.length || 0}</span>
                                </div>
                                <div class="flex justify-between items-center bg-gray-900/50 p-4 rounded-xl border border-white/5">
                                    <span class="text-gray-400 font-medium">Network Hosts</span>
                                    <span class="text-white font-black text-2xl">${data.network?.hosts?.length || 0}</span>
                                </div>
                                <div class="flex justify-between items-center bg-indigo-900/20 p-5 rounded-xl border border-red-500/40 shadow-[0_0_20px_rgba(239,68,68,0.1)]">
                                    <span class="text-gray-300 font-bold">Analysis Score</span>
                                    <span class="text-red-500 font-black text-4xl">${data.malscore || 'N/A'}</span>
                                </div>
                            </div>
                        </div>

                        <!-- Card 4: Full Width Binary Strings -->
                        <div class="md:col-span-2 lg:col-span-3 bg-gray-800/30 p-8 rounded-lg border border-gray-700">
                            <h4 class="text-orange-400 font-bold mb-6 flex items-center gap-3 text-lg uppercase tracking-widest"><i class="fas fa-align-left"></i> Binary Strings (${strings.length})</h4>
                            <div class="strings-container custom-scrollbar max-h-[400px]">
                                ${strings.map(s => `<div class="string-item p-3 text-xs font-mono border-b border-white/5">${s}</div>`).join('')}
                                ${strings.length === 0 ? '<div class="italic text-gray-500 text-lg py-20 text-center">No interesting strings extracted from binary.</div>' : ''}
                            </div>
                        </div>
                    </div>
                `;
                container.innerHTML = html;
            }

            function populateFilesDropped(data) {
                const container = document.getElementById('files-dropped-container');
                if (!container) return;

                const seen = new Set();
                const files = [];

                const addFile = (path, type, proc) => {
                    if (!path || path.length < 3) return;
                    const key = path.toLowerCase();
                    if (seen.has(key)) return;
                    seen.add(key);
                    files.push({ path, type, proc: proc || '' });
                };

                // 1. From behavior summary
                (data.behavior?.summary?.files_created || []).forEach(f => addFile(f, 'Created', ''));
                (data.behavior?.summary?.files_written || []).forEach(f => addFile(f, 'Written', ''));
                (data.behavior?.summary?.files_deleted || []).forEach(f => addFile(f, 'Deleted', ''));
                (data.behavior?.summary?.files_copied || []).forEach(f => addFile(typeof f === 'string' ? f : f.dst || f.src, 'Copied', ''));
                (data.behavior?.summary?.files_moved || []).forEach(f => addFile(typeof f === 'string' ? f : f.dst || f.src, 'Moved', ''));

                // 2. From dropped[] list (CAPE-specific)
                (data.dropped || []).forEach(d => {
                    if (d.name || d.path) addFile(d.path || d.name, 'Dropped', '');
                });

                // 3. From process API calls (WriteFile, CreateFile, CopyFile, MoveFile)
                const fileApiKeywords = ['WriteFile', 'CreateFile', 'CopyFile', 'MoveFile', 'NtCreateFile', 'NtWriteFile'];
                if (files.length < 200 && data.behavior?.processes) {
                    data.behavior.processes.forEach(p => {
                        if (!p.calls) return;
                        p.calls.forEach(c => {
                            if (!fileApiKeywords.some(k => c.api && c.api.includes(k))) return;
                            let filePath = null;
                            if (Array.isArray(c.arguments)) {
                                const pathArg = c.arguments.find(a => ['filepath', 'FileName', 'ExistingFileName', 'NewFileName', 'filename', 'HandleName', 'ObjectName'].includes(a.name));
                                if (pathArg) filePath = pathArg.pretty_value || pathArg.value;
                            } else if (c.arguments) {
                                filePath = c.arguments.filepath || c.arguments.FileName || c.arguments.filename;
                            }
                            if (filePath && /\.[a-zA-Z0-9]{1,5}$/.test(filePath)) {
                                let type = c.api.includes('Write') ? 'Written' : c.api.includes('Copy') ? 'Copied' : c.api.includes('Move') ? 'Moved' : 'Created';
                                addFile(filePath, type, p.process_name);
                            }
                        });
                    });
                }

                if (files.length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state">No dropped files found.</p>';
                    return;
                }

                const iconMap = { 'Created': { icon: 'fa-plus', color: 'text-green-400' }, 'Written': { icon: 'fa-pen', color: 'text-yellow-400' }, 'Deleted': { icon: 'fa-trash', color: 'text-red-400' }, 'Dropped': { icon: 'fa-arrow-down', color: 'text-blue-400' }, 'Copied': { icon: 'fa-copy', color: 'text-purple-400' }, 'Moved': { icon: 'fa-arrows-alt', color: 'text-orange-400' } };

                let html = '<ul class="space-y-2">';
                files.slice(0, 100).forEach(f => {
                    const style = iconMap[f.type] || { icon: 'fa-file', color: 'text-gray-400' };
                    html += `
                    <li class="bg-gray-800 rounded p-2 border border-gray-700 break-all text-xs">
                        <div class="flex items-center mb-1">
                            <i class="fas ${style.icon} ${style.color} mr-2"></i>
                            <span class="font-semibold ${style.color}">${f.type}</span>
                            ${f.proc ? `<span class="ml-auto text-gray-500 font-mono">${f.proc}</span>` : ''}
                        </div>
                        <div class="text-gray-300 font-mono ml-5">${f.path}</div>
                    </li>`;
                });
                if (files.length > 100) html += `<li class="text-center text-gray-500 text-xs py-2">+ ${files.length - 100} more file operations hidden</li>`;
                html += '</ul>';
                container.innerHTML = html;
            }

            function populateProcessTreeOrDns(data) {
                const ptContainer = document.getElementById('process-tree-container');
                if (!ptContainer) return;

                const processes = data.behavior?.processes || [];
                if (processes.length > 0) {
                    ptContainer.innerHTML = '<p class="text-gray-400 text-sm empty-state">Processes will appear here as they spawn.</p>';
                } else {
                    ptContainer.innerHTML = `
                        <div class="flex flex-col items-center justify-center h-full gap-3 text-center">
                            <i class="fas fa-sitemap text-gray-700 text-5xl"></i>
                            <p class="text-gray-400 text-sm font-medium">No process tree available for this sample.</p>
                            <p class="text-gray-600 text-xs">Check the <span class="text-cyan-400">DNS Queries</span> tab for network activity.</p>
                        </div>`;
                }
            }

            // --- TIMELINE LOGIC ---
            function createTimelineEvents(data) {
                const events = []; let time = 0;
                const timeIncrement = 1.5; // seconds between events
                const fileName = data.target?.file?.name || 'sample';

                // Check if benign - use a calmer title
                const score = calculateThreatScore(data);
                if (score === 0 && (!data.signatures || data.signatures.length === 0)) {
                    events.push({ time: time += timeIncrement, type: 'execution', title: 'Sample Executed', data: { name: fileName, benign: true } });
                } else {
                    events.push({ time: time += timeIncrement, type: 'execution', title: 'Malware Executed', data: { name: fileName } });
                }

                // Processes with enhanced info
                if (data.behavior?.processes) data.behavior.processes.forEach(p => {
                    const cmdLine = p.environ?.CommandLine || p.command_line || '';
                    const pData = { ...p };
                    if (cmdLine) pData._cmdLine = cmdLine;

                    // Calculate summary stats for badges
                    const calls = p.calls || [];
                    pData._stats = {
                        file: calls.filter(c => c.category === 'filesystem').length,
                        reg: calls.filter(c => c.category === 'registry').length,
                        net: calls.filter(c => c.category === 'network').length,
                        sync: calls.filter(c => c.category === 'synchronization' || c.category === 'threading').length
                    };

                    events.push({ time: time += timeIncrement, type: 'process', title: `Process Created: ${p.process_name}`, data: pData });
                });

                // Dropped files - files the malware writes/drops during execution
                if (data.dropped && data.dropped.length > 0) {
                    data.dropped.forEach(d => {
                        const droppedName = d.name?.[0] || d.filepath || 'unknown';
                        const shortName = droppedName.split('\\').pop().split('/').pop();
                        const droppedType = d.type || 'unknown type';
                        const droppedSize = d.size ? `${(d.size / 1024).toFixed(1)} KB` : '';
                        events.push({ time: time += timeIncrement, type: 'dropped', title: `File Dropped: ${shortName}`, data: { name: droppedName, shortName, type: droppedType, size: droppedSize, sha256: d.sha256 } });
                    });
                }

                // Files created from behavior summary
                if (data.behavior?.summary?.files_created && data.behavior.summary.files_created.length > 0) {
                    // Deduplicate with dropped files
                    const droppedPaths = new Set((data.dropped || []).map(d => d.name?.[0] || d.filepath || '').map(p => p.toLowerCase()));
                    data.behavior.summary.files_created.forEach(filePath => {
                        if (droppedPaths.has(filePath.toLowerCase())) return; // skip duplicates
                        const shortName = filePath.split('\\').pop().split('/').pop();
                        events.push({ time: time += timeIncrement, type: 'file_created', title: `File Created: ${shortName}`, data: { name: filePath, shortName } });
                    });
                }

                if (data.network?.dns) data.network.dns.forEach(d => events.push({ time: time += timeIncrement, type: 'dns', title: `DNS Query: ${d.request}`, data: d }));
                if (data.network?.hosts) data.network.hosts.forEach(h => events.push({ time: time += timeIncrement, type: 'connection', title: `Connection to ${h.ip}`, data: h }));
                if (data.signatures) data.signatures.forEach(s => {
                    let eventTitle = s.signature ? `Signature: ${s.signature}` : (s.description ? 'Signature Match' : 'Unknown Signature');
                    events.push({ time: time += timeIncrement, type: 'signature', title: eventTitle, data: s });
                });

                // If benign and nothing happened, add a "clean" event
                if (score === 0 && events.length <= 1) {
                    events.push({ time: time += timeIncrement, type: 'clean', title: 'Analysis Complete - No Threats', data: {} });
                }

                return events;
            }

            // --- 3D VISUALIZATION LOGIC ---
            let scene, camera, renderer, labelRenderer, controls, hostSystem, clock, infectionGraphGroup;
            let nodeMap = new Map();
            let networkNodeAngle = 0;
            const processColor = 0xff6b35, dnsColor = 0x4a9eff, ipColor = 0x6bd4ff; // Orange for processes, cyan for network
            let animatedObjects = [];

            function init3DScene() {
                const container = document.getElementById('visualization-3d-container'); container.innerHTML = '';
                if (animationFrameId) cancelAnimationFrame(animationFrameId);
                nodeMap.clear(); networkNodeAngle = 0; animatedObjects = [];
                clock = new THREE.Clock();
                scene = new THREE.Scene();

                // Dark theme background with gradient effect
                scene.background = new THREE.Color(0x0a0e1a);
                scene.fog = new THREE.FogExp2(0x1a1f35, 0.015);

                camera = new THREE.PerspectiveCamera(75, container.clientWidth / container.clientHeight, 0.1, 1000);
                camera.position.set(0, 25, 55);

                renderer = new THREE.WebGLRenderer({ antialias: true, alpha: false });
                renderer.setSize(container.clientWidth, container.clientHeight);
                renderer.setPixelRatio(window.devicePixelRatio);
                renderer.setClearColor(0x0a0e1a, 1);
                container.appendChild(renderer.domElement);

                labelRenderer = new THREE.CSS2DRenderer();
                labelRenderer.setSize(container.clientWidth, container.clientHeight);
                labelRenderer.domElement.style.position = 'absolute';
                labelRenderer.domElement.style.top = '0px';
                labelRenderer.domElement.style.left = '0px';
                labelRenderer.domElement.style.pointerEvents = 'none';
                labelRenderer.domElement.style.zIndex = '1000';
                container.appendChild(labelRenderer.domElement);

                controls = new THREE.OrbitControls(camera, container);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;
                controls.minDistance = 8;
                controls.maxDistance = 150;
                controls.enablePan = true;
                controls.autoRotate = false;
                // Allow more vertical rotation to see from different angles
                controls.maxPolarAngle = Math.PI;

                // Enhanced lighting setup
                const ambient = new THREE.AmbientLight(0x2a3a5a, 0.8);
                scene.add(ambient);

                // Main directional light (cool blue)
                const mainLight = new THREE.DirectionalLight(0x4a9eff, 1.2);
                mainLight.position.set(10, 20, 15);
                mainLight.castShadow = false;
                scene.add(mainLight);

                // Accent lights for dramatic effect
                const accentLight1 = new THREE.PointLight(0xff6b35, 1, 50);
                accentLight1.position.set(-15, 10, -15);
                scene.add(accentLight1);

                const accentLight2 = new THREE.PointLight(0x4a9eff, 0.8, 50);
                accentLight2.position.set(15, 10, 15);
                scene.add(accentLight2);

                // Create 3D topographical base (grid-like terrain)
                const gridHelper = new THREE.GridHelper(80, 80, 0x2a3a5a, 0x1a2440);
                gridHelper.position.y = -2;
                scene.add(gridHelper);

                // Add a subtle plane for depth
                const planeGeometry = new THREE.PlaneGeometry(100, 100, 20, 20);
                const planeMaterial = new THREE.MeshStandardMaterial({
                    color: 0x1a2440,
                    emissive: 0x0d1525,
                    emissiveIntensity: 0.3,
                    wireframe: false,
                    transparent: true,
                    opacity: 0.4
                });
                const plane = new THREE.Mesh(planeGeometry, planeMaterial);
                plane.rotation.x = -Math.PI / 2;
                plane.position.y = -2.1;
                scene.add(plane);

                // Enhanced host system with better visual
                const coreGeo = new THREE.IcosahedronGeometry(5, 2);
                const coreMat = new THREE.MeshStandardMaterial({
                    color: 0x4a9eff,
                    transparent: true,
                    opacity: 0.15,
                    wireframe: true,
                    emissive: 0x4a9eff,
                    emissiveIntensity: 0.3
                });
                hostSystem = new THREE.Mesh(coreGeo, coreMat);
                hostSystem.position.y = -1;
                scene.add(hostSystem);

                // Add pulsing glow effect to host system
                const glowGeo = new THREE.IcosahedronGeometry(5.5, 2);
                const glowMat = new THREE.MeshBasicMaterial({
                    color: 0x4a9eff,
                    transparent: true,
                    opacity: 0.1,
                    wireframe: true
                });
                const hostGlow = new THREE.Mesh(glowGeo, glowMat);
                hostSystem.add(hostGlow);

                const coreLabel = createLabel('Host System');
                coreLabel.position.set(0, 7, 0);
                hostSystem.add(coreLabel);

                infectionGraphGroup = new THREE.Group();
                infectionGraphGroup.position.y = 0;
                scene.add(infectionGraphGroup);

                animate3D();
            }

            function onWindowResize() {
                const c = document.getElementById('visualization-3d-container'); if (!c) return;
                camera.aspect = c.clientWidth / c.clientHeight; camera.updateProjectionMatrix();
                renderer.setSize(c.clientWidth, c.clientHeight); labelRenderer.setSize(c.clientWidth, c.clientHeight);
                // Keep map overlay in sync with container size
                rebuildPolyline();
            }

            function toggleFullscreen() {
                const container = document.getElementById('visualization-card');
                if (!container) return;

                if (!document.fullscreenElement) {
                    if (container.requestFullscreen) {
                        container.requestFullscreen();
                    } else if (container.webkitRequestFullscreen) {
                        container.webkitRequestFullscreen();
                    } else if (container.msRequestFullscreen) {
                        container.msRequestFullscreen();
                    }
                } else {
                    if (document.exitFullscreen) {
                        document.exitFullscreen();
                    } else if (document.webkitExitFullscreen) {
                        document.webkitExitFullscreen();
                    } else if (document.msExitFullscreen) {
                        document.msExitFullscreen();
                    }
                }
            }

            function togglePause() {
                isPaused = !isPaused;
                playPauseBtn.querySelector('i').className = isPaused ? 'fas fa-play' : 'fas fa-pause';
            }

            function setSpeed(e) {
                playbackSpeed = parseFloat(e.currentTarget.dataset.speed);
                speedBtns.forEach(btn => btn.classList.remove('active'));
                e.currentTarget.classList.add('active');
            }

            function trigger3DAnimation(event) {
                switch (event.type) {
                    case 'execution': createInitialNode(event.data); break;
                    case 'process': createProcessNode(event.data); break;
                    case 'dns': createNetworkNode(event.data, 'dns'); break;
                    case 'connection': createNetworkNode(event.data, 'ip'); break;
                    case 'signature': highlightNodeBySignature(event.data); break;
                }
            }

            function createLabel(text, ip = null) {
                const div = document.createElement('div');
                div.className = 'label';

                if (ip) {
                    div.innerHTML = `${text}<div class="ip">${ip}</div>`;
                } else {
                    div.textContent = text;
                }

                return new THREE.CSS2DObject(div);
            }

            function createNode(name, color, size = 0.5, ip = null) {
                const geo = new THREE.SphereGeometry(size, 16, 16);
                const mat = new THREE.MeshStandardMaterial({
                    color,
                    emissive: color,
                    emissiveIntensity: 0.6,
                    metalness: 0.8,
                    roughness: 0.2
                });
                const node = new THREE.Mesh(geo, mat);

                // Add outer glow effect
                const glowGeo = new THREE.SphereGeometry(size * 1.3, 16, 16);
                const glowMat = new THREE.MeshBasicMaterial({
                    color: color,
                    transparent: true,
                    opacity: 0.2,
                    side: THREE.BackSide
                });
                const glow = new THREE.Mesh(glowGeo, glowMat);
                node.add(glow);

                // Add particle activity around node (orange/yellow specks)
                const particleCount = 8;
                const particleGroup = new THREE.Group();
                for (let i = 0; i < particleCount; i++) {
                    const particleSize = 0.05 + Math.random() * 0.05;
                    const particleGeo = new THREE.SphereGeometry(particleSize, 8, 8);
                    const particleColor = i % 2 === 0 ? 0xff6b35 : 0xffd93d; // Orange or yellow
                    const particleMat = new THREE.MeshBasicMaterial({
                        color: particleColor,
                        emissive: particleColor,
                        emissiveIntensity: 1,
                        transparent: true,
                        opacity: 0.7
                    });
                    const particle = new THREE.Mesh(particleGeo, particleMat);

                    const angle = (i / particleCount) * Math.PI * 2;
                    const radius = size * 2 + Math.random() * size;
                    particle.position.set(
                        Math.cos(angle) * radius,
                        (Math.random() - 0.5) * size * 2,
                        Math.sin(angle) * radius
                    );
                    particle.userData = { baseAngle: angle, radius: radius, speed: 0.5 + Math.random() * 0.5 };
                    particleGroup.add(particle);
                }
                node.add(particleGroup);
                node.userData.particleGroup = particleGroup;

                const label = createLabel(name, ip);
                // Position label higher above node to avoid overlap
                label.position.set(0, size + 1.2, 0);
                node.add(label);
                node.userData = { ...node.userData, childCount: 0 };
                node.scale.set(0.01, 0.01, 0.01);
                animatedObjects.push({ type: 'scaleIn', object: node, progress: 0 });
                return node;
            }

            function createLine(pos1, pos2) {
                // Main glowing cyan line
                const mat = new THREE.LineBasicMaterial({
                    color: 0x4a9eff,
                    transparent: true,
                    opacity: 0,
                    linewidth: 2
                });
                const geo = new THREE.BufferGeometry().setFromPoints([pos1, pos2]);
                const line = new THREE.Line(geo, mat);

                // Add glowing trail effect
                const trailMat = new THREE.LineBasicMaterial({
                    color: 0x6bd4ff,
                    transparent: true,
                    opacity: 0,
                    linewidth: 1
                });
                const trail = new THREE.Line(geo.clone(), trailMat);
                line.add(trail);
                line.userData.trail = trail;

                animatedObjects.push({ type: 'fadeIn', object: line, progress: 0 });
                return line;
            }

            function createInitialNode(data) {
                const node = createNode(data.name, 0xff1744, 1.0); // Brighter red for malware origin
                // Add extra particles for the initial malware node
                if (node.userData && node.userData.particleGroup) {
                    // Add more particles to show infection spread
                    for (let i = 0; i < 12; i++) {
                        const particleSize = 0.08 + Math.random() * 0.08;
                        const particleGeo = new THREE.SphereGeometry(particleSize, 8, 8);
                        const particleColor = 0xff4444; // Red particles for malware
                        const particleMat = new THREE.MeshBasicMaterial({
                            color: particleColor,
                            emissive: particleColor,
                            emissiveIntensity: 1.2,
                            transparent: true,
                            opacity: 0.8
                        });
                        const particle = new THREE.Mesh(particleGeo, particleMat);

                        const angle = (i / 12) * Math.PI * 2;
                        const radius = 1.5 + Math.random() * 0.5;
                        particle.position.set(
                            Math.cos(angle) * radius,
                            (Math.random() - 0.5) * 1.5,
                            Math.sin(angle) * radius
                        );
                        particle.userData = { baseAngle: angle, radius: radius, speed: 0.8 + Math.random() * 0.4 };
                        node.userData.particleGroup.add(particle);
                    }
                }
                infectionGraphGroup.add(node);
                nodeMap.set('initial', node);
                const firstProcess = reportData.behavior?.processes?.[0];
                if (firstProcess) nodeMap.set(firstProcess.pid, node);
            }

            function renderLabel(node, div) {
                let countBadge = '';
                if (node.userData.count > 1) {
                    countBadge = `<span style="background-color:#4f46e5; color:white; border-radius:4px; padding:2px 5px; margin-left:6px; font-size:10px;">${node.userData.count}</span>`;
                }

                if (node.userData.isProcess) {
                    let text = `${node.userData.processName}${countBadge}`;
                    if (node.userData.expanded) {
                        let tableHTML = '<table style="width:100%; text-align:left; border-collapse:collapse; margin-top:4px;">';
                        tableHTML += '<tr style="border-bottom:1px solid #4f46e5;"><th style="padding:2px 0;">PID</th></tr>';
                        node.userData.pids.forEach(pid => {
                            tableHTML += `<tr><td style="padding:2px 0;">${pid}</td></tr>`;
                        });
                        tableHTML += '</table>';

                        text += `<div class="label-scroll-area" style="font-size:10px; color:#a5b4fc; margin-top:4px; max-height:150px; overflow-y:auto; text-align:left; background:rgba(0,0,0,0.8); padding:6px; border-radius:4px; white-space:normal; pointer-events:auto;">${tableHTML}</div>`;
                    }
                    div.innerHTML = text;
                } else if (node.userData.isNetwork) {
                    let text = `${node.userData.networkName}${countBadge}`;
                    if (node.userData.networkIp) {
                        text += `<div class="ip">${node.userData.networkIp}</div>`;
                    }
                    if (node.userData.expanded) {
                        let tableHTML = '<table style="width:100%; text-align:left; border-collapse:collapse; margin-top:4px; font-size:9px;">';
                        tableHTML += '<tr style="border-bottom:1px solid #4f46e5;"><th style="padding:2px 0;">Details</th></tr>';
                        node.userData.events.forEach(ev => {
                            let info = '';
                            if (ev.answers) {
                                const answers = ev.answers.map(a => a.data).slice(0, 2).join(', ');
                                info = `DNS ${ev.type}${answers ? ' &rarr; ' + answers : ''}`;
                            } else if (ev.port) {
                                info = `Port: ${ev.port}`;
                            } else {
                                info = ev.type || 'Connection';
                            }
                            tableHTML += `<tr><td style="padding:2px 0; overflow:hidden; text-overflow:ellipsis; max-width:180px;" title="${info}">${info}</td></tr>`;
                        });
                        tableHTML += '</table>';

                        text += `<div class="label-scroll-area" style="font-size:10px; color:#a5b4fc; margin-top:4px; max-height:150px; overflow-y:auto; background:rgba(0,0,0,0.8); padding:6px; border-radius:4px; white-space:normal; pointer-events:auto;">${tableHTML}</div>`;
                    }
                    div.innerHTML = text;
                } else {
                    div.innerHTML = node.userData.processName || 'Node';
                }

                // Prevent interaction leakage to 3D scene
                const scrollArea = div.querySelector('.label-scroll-area');
                if (scrollArea) {
                    const stop = (e) => e.stopPropagation();
                    scrollArea.addEventListener('click', stop);
                    scrollArea.addEventListener('wheel', stop);
                    scrollArea.addEventListener('mousedown', stop);
                    scrollArea.addEventListener('touchstart', stop);
                }
            }

            function createProcessNode(data) {
                // Handle missing PIDs/PPIDs safely to prevent `null` key chaining
                const ppid = (data.ppid === null || data.ppid === undefined) ? 'unknown_parent' : data.ppid;
                const pid = (data.pid === null || data.pid === undefined) ? `unknown_pid_${Math.random()}` : data.pid;

                const parentNode = nodeMap.get(ppid) || nodeMap.get('initial');
                if (!parentNode) return;

                if (!parentNode.userData.childrenByName) {
                    parentNode.userData.childrenByName = new Map();
                }

                let baseName = String(data.process_name || 'unknown').trim();
                // Match the first word (ignoring arguments) so "nslookup.exe domain.com" groups under "nslookup.exe"
                const firstWordMatch = baseName.match(/^([^\s]+)/);
                if (firstWordMatch) {
                    baseName = firstWordMatch[1];
                }
                const processKey = baseName.toLowerCase();

                let node = parentNode.userData.childrenByName.get(processKey);

                if (node) {
                    node.userData.count++;
                    if (!node.userData.pids.includes(pid)) {
                        node.userData.pids.push(pid);
                    }
                    const labelObj = node.children.find(c => c.isCSS2DObject);
                    if (labelObj) {
                        renderLabel(node, labelObj.element);
                    }
                    nodeMap.set(pid, node); // Route future children through this node
                    return;
                }

                node = createNode(baseName, processColor);
                node.userData.isProcess = true;
                node.userData.processName = baseName;
                node.userData.count = 1;
                node.userData.pids = [pid];
                node.userData.expanded = false;

                const labelObj = node.children.find(c => c.isCSS2DObject);
                if (labelObj) {
                    labelObj.element.addEventListener('click', (e) => {
                        e.stopPropagation();
                        if (node.userData.count > 1) {
                            node.userData.expanded = !node.userData.expanded;
                            renderLabel(node, labelObj.element);
                        }
                    });
                    renderLabel(node, labelObj.element);
                }

                const childIndex = parentNode.userData.childCount++;
                const goldenAngle = Math.PI * (3 - Math.sqrt(5)); // ~137.5 degrees
                const angle = childIndex * goldenAngle;
                const radius = 5.0 * Math.sqrt(childIndex + 1); // Increased from 3.0
                const yOffset = (childIndex % 2 === 0 ? 1 : -1) * (childIndex * 1.5); // Increased from 0.6

                node.position.set(
                    parentNode.position.x + Math.cos(angle) * radius,
                    parentNode.position.y + yOffset,
                    parentNode.position.z + Math.sin(angle) * radius
                );

                infectionGraphGroup.add(node);
                infectionGraphGroup.add(createLine(parentNode.position, node.position));
                parentNode.userData.childrenByName.set(processKey, node);
                nodeMap.set(pid, node);
            }

            function createNetworkNode(data, type) {
                let parentNode = nodeMap.get(data.pid) || Array.from(nodeMap.values()).filter(n => n.material.color.getHex() === processColor).pop() || nodeMap.get('initial');
                if (!parentNode) return;
                const name = type === 'dns' ? data.request : data.ip;
                const color = type === 'dns' ? dnsColor : ipColor;

                const networkKey = String(name || 'unknown').toLowerCase().trim();
                let node = nodeMap.get(networkKey);

                if (!node) {
                    let locationName = name;
                    let ipToShow = null;

                    if (type === 'ip') {
                        locationName = name;
                        ipToShow = null;
                        fetchGeolocation(data.ip, networkKey);
                    }

                    node = createNode(locationName, color, 0.6, ipToShow);
                    node.userData.isNetwork = true;
                    node.userData.networkName = locationName;
                    node.userData.networkIp = ipToShow;
                    node.userData.count = 1;
                    node.userData.events = [data];
                    node.userData.expanded = false;

                    const labelObj = node.children.find(c => c.isCSS2DObject);
                    if (labelObj) {
                        labelObj.element.addEventListener('click', (e) => {
                            e.stopPropagation();
                            if (node.userData.count > 1) {
                                node.userData.expanded = !node.userData.expanded;
                                renderLabel(node, labelObj.element);
                            }
                        });
                        renderLabel(node, labelObj.element);
                    }

                    const angle = networkNodeAngle;
                    networkNodeAngle += Math.PI / 6; // Less dense packing
                    const radius = 60 + Math.random() * 30;
                    const height = (Math.random() - 0.5) * 50;
                    node.position.set(Math.cos(angle) * radius, height, Math.sin(angle) * radius);
                    infectionGraphGroup.add(node);
                    nodeMap.set(networkKey, node);

                    const line = createLine(parentNode.position, node.position);
                    infectionGraphGroup.add(line);
                } else {
                    node.userData.count++;
                    node.userData.events.push(data);
                    const labelObj = node.children.find(c => c.isCSS2DObject);
                    if (labelObj) {
                        renderLabel(node, labelObj.element);
                    }
                }

                createPacket(parentNode.position, node.position);
            }

            function fetchGeolocation(ip, nodeName) {
                // Strategy: try the server-side proxy first (works behind firewalls),
                // then fall back to direct browser API calls as a last resort.

                // 1. Try server proxy (handles all API fallbacks server-side)
                fetch(`/api/geoip/${ip}`)
                    .then(response => {
                        if (!response.ok) throw new Error('Proxy returned ' + response.status);
                        return response.json();
                    })
                    .then(data => {
                        if (data.location && data.location !== 'Unknown, Unknown, Unknown') {
                            updateLocationData(ip, nodeName, data.location, data.lat, data.lon);
                        } else {
                            throw new Error('Invalid proxy data');
                        }
                    })
                    .catch(proxyErr => {
                        console.warn(`Server proxy failed for ${ip}, trying direct APIs:`, proxyErr.message);
                        // 2. Fall back to direct browser API calls
                        tryDirectApis(ip, nodeName);
                    });
            }

            function tryDirectApis(ip, nodeName) {
                const apis = [
                    `https://ipapi.co/${ip}/json/`,
                    `https://ipwhois.app/json/${ip}`,
                    `https://json.geoiplookup.io/${ip}`,
                    `https://api.ip.sb/geoip/${ip}`
                ];

                let currentApiIndex = 0;

                function tryNextApi() {
                    if (currentApiIndex >= apis.length) {
                        updateLocationData(ip, nodeName, 'Location unavailable');
                        return;
                    }

                    const apiUrl = apis[currentApiIndex];
                    currentApiIndex++;

                    fetch(apiUrl)
                        .then(response => {
                            if (!response.ok) throw new Error('API response not ok');
                            return response.json();
                        })
                        .then(data => {
                            const lat = data.latitude || data.lat || null;
                            const lon = data.longitude || data.lon || data.lng || null;

                            let location;
                            if (apiUrl.includes('ipapi.co')) {
                                location = `${data.city || 'Unknown'}, ${data.region || 'Unknown'}, ${data.country_name || 'Unknown'}`;
                            } else if (apiUrl.includes('ipwhois.app')) {
                                location = `${data.city || 'Unknown'}, ${data.region || 'Unknown'}, ${data.country || 'Unknown'}`;
                            } else if (apiUrl.includes('geoiplookup.io')) {
                                location = `${data.city || 'Unknown'}, ${data.region || 'Unknown'}, ${data.country_name || 'Unknown'}`;
                            } else if (apiUrl.includes('ip.sb')) {
                                location = `${data.city || 'Unknown'}, ${data.region || 'Unknown'}, ${data.country || 'Unknown'}`;
                            } else {
                                location = `${data.city || 'Unknown'}, ${data.region || 'Unknown'}, ${data.country_name || data.country || 'Unknown'}`;
                            }

                            if (location === 'Unknown, Unknown, Unknown' || !location) {
                                throw new Error('Invalid location data');
                            }

                            updateLocationData(ip, nodeName, location, lat ? parseFloat(lat) : null, lon ? parseFloat(lon) : null);
                        })
                        .catch(error => {
                            console.warn(`Direct API ${apiUrl} failed:`, error.message);
                            tryNextApi();
                        });
                }

                tryNextApi();
            }

            function updateLocationData(ip, nodeName, location, lat = null, lon = null) {
                // Store object with location and optional coordinates
                geolocationData[ip] = { location, lat: lat || null, lon: lon || null };
                updateGeolocationDisplay();

                // Update the node label with the actual location
                const node = nodeMap.get(nodeName);
                if (node) {
                    node.userData.networkName = location;
                    node.userData.networkIp = ip;
                    // Find the label (CSS2DObject) among all children
                    let label = null;
                    for (let i = 0; i < node.children.length; i++) {
                        if (node.children[i].isCSS2DObject) {
                            label = node.children[i];
                            break;
                        }
                    }
                    if (label && label.element) {
                        renderLabel(node, label.element);
                    }
                }

                // Update timeline events for this IP
                if (timelineEventsByIP[ip]) {
                    timelineEventsByIP[ip].forEach(timelineItem => {
                        const locationBadge = timelineItem.querySelector('.timeline-location');
                        if (locationBadge) {
                            locationBadge.textContent = location;
                        } else {
                            // Create a location badge if it doesn't exist
                            const badge = document.createElement('div');
                            badge.className = 'timeline-location';
                            badge.textContent = location;
                            timelineItem.querySelector('p').appendChild(badge);
                        }
                    });
                }

                // Draw or update a pin on the map if coordinates are available
                if (lat !== null && lon !== null) {
                    drawMapPin(ip, lat, lon, location);
                    // If globe is active, refresh globe datasets
                    if (globeInstance) {
                        // ensure globePoints updated
                        refreshGlobeData();
                        // animate the point appearance
                        const p = globePoints.find(pt => pt.ip === ip);
                        if (p) {
                            // pulse via GSAP by temporarily increasing size
                            gsap.fromTo(p, { size: 0.02 }, { size: 0.12, duration: 0.5, yoyo: true, repeat: 1, onUpdate: () => globeInstance.pointsData(globePoints) });
                        }
                    }
                }
                // ensure all views stay in sync after a location update
                syncAllViews();
            }
            function initMapInteractions() {
                if (!document.getElementById('world-map')) return;
                leafletMap = L.map('world-map', {
                    center: [20, 0],
                    zoom: 2,
                    minZoom: 2,
                    zoomControl: false,
                    attributionControl: false,
                    maxBounds: [[-90, -180], [90, 180]],
                    maxBoundsViscosity: 1.0
                });
                // Dark theme tile layer
                L.tileLayer('https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png', {
                    maxZoom: 19,
                    noWrap: false,
                    bounds: [[-90, -180], [90, 180]]
                }).addTo(leafletMap);
            }

            function changeMapZoom(factor) {
                if (currentView === 'map') {
                    if (leafletMap) {
                        if (factor > 1) leafletMap.zoomIn();
                        else leafletMap.zoomOut();
                    }
                } else if (controls && camera) {
                    const zoomVector = new THREE.Vector3().subVectors(camera.position, controls.target);
                    zoomVector.multiplyScalar(factor < 1 ? 1.2 : 1 / 1.2);
                    camera.position.copy(controls.target).add(zoomVector);
                    controls.update();
                }
            }

            function panView(direction) {
                if (currentView === 'map' && leafletMap) {
                    const offset = direction === 'left' ? [-100, 0] :
                        direction === 'right' ? [100, 0] :
                            direction === 'up' ? [0, -100] : [0, 100];
                    leafletMap.panBy(offset);
                } else if (currentView === '3d' && controls && camera) {
                    const panStep = 5;
                    if (direction === 'left') { camera.position.x -= panStep; controls.target.x -= panStep; }
                    else if (direction === 'right') { camera.position.x += panStep; controls.target.x += panStep; }
                    else if (direction === 'up') { camera.position.y += panStep; controls.target.y += panStep; }
                    else if (direction === 'down') { camera.position.y -= panStep; controls.target.y -= panStep; }
                    controls.update();
                }
            }

            function resetMap() {
                if (currentView === 'map') {
                    if (leafletMap) leafletMap.setView([20, 0], 2);
                } else if (controls && camera) {
                    camera.position.set(0, 25, 55);
                    controls.target.set(0, 0, 0);
                    controls.update();
                }
            }

            function drawMapPin(ip, lat, lon, location) {
                if (!leafletMap) return;
                if (typeof lat !== 'number' || typeof lon !== 'number' || Number.isNaN(lat) || Number.isNaN(lon)) return;

                let pin = mapPins[ip];
                if (!pin) {
                    const iconHtml = `
                        <div class="location-pin pin-new" style="position:static;">
                            <svg width="28" height="28" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
                              <path d="M12 2C8.13401 2 5 5.13401 5 9C5 14.25 12 22 12 22C12 22 19 14.25 19 9C19 5.13401 15.866 2 12 2Z" fill="#ef4444"/>
                              <circle cx="12" cy="9" r="2.5" fill="#fff"/>
                            </svg>
                            <div class="location-label">${location}<div class="ip" style="font-size:10px;margin-top:4px;opacity:0.9">${ip}</div></div>
                        </div>
                    `;
                    const divIcon = L.divIcon({ html: iconHtml, className: '', iconSize: [28, 28], iconAnchor: [14, 28] });
                    pin = L.marker([lat, lon], { icon: divIcon }).addTo(leafletMap);

                    const markerEl = pin.getElement();
                    if (markerEl) {
                        markerEl.addEventListener('mouseenter', () => markerEl.querySelector('.location-pin').classList.add('active'));
                        markerEl.addEventListener('mouseleave', () => markerEl.querySelector('.location-pin').classList.remove('active'));
                    }

                    pin.on('click', () => {
                        if (timelineEventsByIP[ip]) {
                            timelineEventsByIP[ip].forEach(it => { it.classList.add('active'); setTimeout(() => it.classList.remove('active'), 1500); });
                        }
                        leafletMap.setView([lat, lon], 6, { animate: true });
                        showPinPopup(ip, lat, lon, location);
                    });

                    mapPins[ip] = pin;
                } else {
                    pin.setLatLng([lat, lon]);
                }
                rebuildPolyline();
            }

            function draw2DConnection(ipA, ipB, color = '#ff6b35', duration = 2800) {
                if (!connectionSequence.includes(ipA)) connectionSequence.push(ipA);
                if (!connectionSequence.includes(ipB)) connectionSequence.push(ipB);
                rebuildPolyline();
            }

            function rebuildPolyline() {
                if (!leafletMap) return;
                if (currentPolyline) {
                    leafletMap.removeLayer(currentPolyline);
                    currentPolyline = null;
                }
                if (connectionSequence.length < 2) return;

                const latlngs = [];
                const seq = connectionSequence.filter((ip, i, arr) => i === 0 || ip !== arr[i - 1]);
                for (const ip of seq) {
                    const marker = mapPins[ip];
                    if (marker && marker.getLatLng) {
                        latlngs.push(marker.getLatLng());
                    }
                }

                if (latlngs.length >= 2) {
                    currentPolyline = L.polyline(latlngs, {
                        color: '#ef4444',
                        weight: 2,
                        opacity: 0.9,
                        dashArray: '5, 10'
                    }).addTo(leafletMap);
                }
            }

            function showPinPopup(ip, lat, lon, info) {
                if (!document.getElementById('world-map')) return;
                // lazy-create popup
                if (!pinPopup) {
                    pinPopup = document.createElement('div');
                    pinPopup.id = 'pin-popup';
                    pinPopup.style.position = 'absolute';
                    pinPopup.style.zIndex = 1000;
                    pinPopup.style.minWidth = '200px';
                    pinPopup.style.background = 'rgba(17,24,39,0.95)';
                    pinPopup.style.color = '#fff';
                    pinPopup.style.padding = '10px';
                    pinPopup.style.borderRadius = '8px';
                    pinPopup.style.border = '1px solid rgba(74,158,255,0.15)';
                    pinPopup.style.boxShadow = '0 8px 24px rgba(0,0,0,0.6)';
                    pinPopup.style.pointerEvents = 'auto';
                    pinPopup.style.transition = 'transform 200ms ease, opacity 200ms ease';

                    // Add close button
                    const closeBtn = document.createElement('button');
                    closeBtn.innerHTML = '<i class="fas fa-times"></i>';
                    closeBtn.style.position = 'absolute';
                    closeBtn.style.right = '5px';
                    closeBtn.style.top = '5px';
                    closeBtn.style.color = '#9ca3af';
                    closeBtn.style.cursor = 'pointer';
                    closeBtn.onclick = () => pinPopup.style.opacity = '0';
                    pinPopup.appendChild(closeBtn);

                    const contentDiv = document.createElement('div');
                    contentDiv.className = 'popup-content';
                    pinPopup.appendChild(contentDiv);

                    document.getElementById('world-map').appendChild(pinPopup);
                }
                // Build content: IP, location, and recent events
                const gd = geolocationData[ip] || {};
                const events = timelineEventsByIP[ip] || [];
                let html = `<div style="font-weight:600;margin-bottom:6px">${gd.location || info || 'Unknown location'}</div>`;
                html += `<div style="font-family:monospace;color:#c7d2fe;margin-bottom:6px">${ip}</div>`;
                if (events.length > 0) {
                    html += '<div style="font-size:12px;color:#9ca3af;margin-bottom:6px">Recent events</div><ul style="max-height:120px;overflow:auto;padding-left:16px;margin:0 0 6px 0">';
                    events.slice(-6).forEach(it => html += `<li style="font-size:12px;color:#e5e7eb;margin-bottom:4px">${it.querySelector('h3')?.textContent || ''}</li>`);
                    html += '</ul>';
                }
                html += `<div style="display:flex;gap:8px;justify-content:flex-end"><button id="popup-center" style="background:#4f46e5;color:white;padding:6px 8px;border-radius:6px;border:none">Center</button><button id="popup-close" style="background:transparent;border:1px solid #374151;color:#cbd5e1;padding:6px 8px;border-radius:6px">Close</button></div>`;
                pinPopup.innerHTML = html;

                // position popup relative to pin
                const containerRect = geolocationMapContainer.getBoundingClientRect();
                const popupW = 220, popupH = 160;
                let left = 20, top = 20;
                pinPopup.style.left = `${left}px`;
                pinPopup.style.top = `${top}px`;
                pinPopup.style.opacity = '1';

                // wire buttons
                document.getElementById('popup-center').onclick = () => centerOnCoordinates(lat, lon, 6);
                document.getElementById('popup-close').onclick = () => { pinPopup.style.opacity = '0'; setTimeout(() => { if (pinPopup) pinPopup.remove(); pinPopup = null; }, 200); };
            }

            function hidePinPopup() {
                if (pinPopup) { pinPopup.remove(); pinPopup = null; }
            }


            function toggleMapView() {
                const desired = currentView === '3d' ? 'map' : '3d';
                performViewSwitch(desired);
            }

            function performViewSwitch(targetView) {
                if (targetView === 'map') {
                    geolocationMapContainer.classList.remove('hidden');
                    visualization3dContainer.classList.add('hidden');
                    viewToggleBtn.querySelector('i').className = 'fas fa-network-wired mr-1';
                    viewToggleBtn.querySelector('span').textContent = '3D View';
                    currentView = 'map';
                    // Ensure pins are positioned after layout is updated
                    requestAnimationFrame(() => {
                        for (const [ip, info] of Object.entries(geolocationData)) {
                            if (info && info.lat !== null && info.lon !== null) drawMapPin(ip, info.lat, info.lon, info.location);
                        }
                        if (leafletMap) {
                            setTimeout(() => {
                                leafletMap.invalidateSize();
                                leafletMap.setView([20, 0], leafletMap.getZoom(), { animate: false });
                            }, 100);
                        }
                        rebuildPolyline();
                    });
                } else {
                    geolocationMapContainer.classList.add('hidden');
                    visualization3dContainer.classList.remove('hidden');
                    viewToggleBtn.querySelector('i').className = 'fas fa-map mr-1';
                    viewToggleBtn.querySelector('span').textContent = 'Map View';
                    currentView = '3d';
                    // Ensure 3D scene is initialized and sized when showing
                    const container = document.getElementById('visualization-3d-container');
                    if (!renderer || !container || !container.firstChild) {
                        init3DScene();
                    }
                    setTimeout(onWindowResize, 50);
                }
            }

            function initGlobe() {
                try {
                    // create globe in the same container
                    globeInstance = Globe();
                    // append globe canvas inside geolocation-map-container (or #world-map)
                    const globeContainer = document.getElementById('world-map');
                    globeContainer.innerHTML = '';
                    globeContainer.appendChild(globeInstance.domElement || globeInstance.renderer().domElement);
                    if (worldSvg) worldSvg.style.display = 'none';
                    globeInstance.width(globeContainer.clientWidth).height(globeContainer.clientHeight)
                        .showAtmosphere(true)
                        .atmosphereColor('#2a3a5a')
                        .pointOfView({ lat: 20, lng: 0, altitude: 2.5 });

                    globeInstance.onPointHover((point) => {
                        if (!point) return;
                        // enlarge the hovered point and pulse
                        gsap.to(point, { size: Math.min(0.25, (point.size || 0.06) * 1.8), duration: 0.25, onUpdate: () => globeInstance.pointsData(globePoints) });
                    });

                    globeInstance.onPointClick((point) => { if (point) { centerOnCoordinates(point.lat, point.lng, 700); showGlobePopup(point); } });

                    // initial empty data
                    globeInstance.pointsData(globePoints).arcsData(globeArcs)
                        .pointAltitude('size')
                        .pointColor('color')
                        .pointRadius(0.35)
                        .arcDashLength(0.4)
                        .arcDashGap(0.16)
                        .arcDashAnimateTime(2200)
                        .arcColor('color')
                        .arcAltitude(0.25);
                } catch (e) {
                    console.warn('Globe initialization failed:', e);
                    globeInstance = null;
                }
            }

            // Sync state between 3D scene, 2D map pins, geolocation panel and globe.
            function syncAllViews() {
                // Update geolocation panel
                updateGeolocationDisplay();

                // Ensure 2D pins exist for all known geolocations
                for (const [ip, info] of Object.entries(geolocationData)) {
                    if (info && info.lat != null && info.lon != null) {
                        drawMapPin(ip, info.lat, info.lon, info.location);
                    }
                }

                // Update 3D node labels to reflect newly discovered geolocation info (if any)
                // Node keys for IP nodes are stored as the ip string in nodeMap
                nodeMap.forEach((node, key) => {
                    // if this node corresponds to an IP that we have geolocation for, update its CSS2D label
                    if (geolocationData[key]) {
                        const gd = geolocationData[key];
                        for (let i = 0; i < node.children.length; i++) {
                            const child = node.children[i];
                            if (child.isCSS2DObject && child.element) {
                                child.element.innerHTML = `${gd.location}<div class="ip">${key}</div>`;
                                break;
                            }
                        }
                    }
                });

                // Refresh globe dataset if globe is present
                if (globeInstance) {
                    refreshGlobeData();
                }
            }

            function setGlobeTexture(url) {
                if (!globeInstance) return;
                try {
                    globeInstance.globeImageUrl(url);
                } catch (e) {
                    console.warn('Failed to set globe texture:', e);
                }
            }

            function addTemporaryArc(startLat, startLng, endLat, endLng, color = '#ff6b35', duration = 3000) {
                if (!globeInstance) return;
                const arc = { startLat, startLng, endLat, endLng, color };
                globeArcs.push(arc);
                globeInstance.arcsData(globeArcs);
                // remove after duration and refresh
                setTimeout(() => {
                    const idx = globeArcs.indexOf(arc);
                    if (idx !== -1) {
                        globeArcs.splice(idx, 1);
                        globeInstance.arcsData(globeArcs);
                    }
                }, duration);
            }

            function refreshGlobeData() {
                if (!globeInstance) return;
                // sync globePoints with geolocationData
                globePoints = Object.entries(geolocationData).filter(([ip, info]) => info && info.lat != null && info.lon != null).map(([ip, info]) => ({ lat: info.lat, lng: info.lon, size: 0.06, color: 'red', ip, label: info.location }));
                // build arcs from timeline
                buildArcsFromTimeline();
                globeInstance.pointsData(globePoints).arcsData(globeArcs);
            }

            function showGlobePopup(point) {
                if (!point) return;
                // reuse existing DOM popup if available
                showPinPopup(point.ip, point.lat, point.lng, point.label);
            }

            function buildArcsFromTimeline() {
                globeArcs = [];
                // collect connection-type events in chronological order with coordinates
                const seq = [];
                for (let ev of timelineEvents) {
                    if (ev.type === 'connection' && ev.data && ev.data.ip) {
                        const info = geolocationData[ev.data.ip];
                        if (info && info.lat != null && info.lon != null) seq.push({ ip: ev.data.ip, lat: info.lat, lon: info.lon });
                    }
                }
                // create arcs between consecutive distinct points
                for (let i = 1; i < seq.length; i++) {
                    const a = seq[i - 1], b = seq[i];
                    if (a.ip === b.ip) continue;
                    globeArcs.push({ startLat: a.lat, startLng: a.lon, endLat: b.lat, endLng: b.lon, color: ['#ff6b35', '#4a9eff'][i % 2] });
                }
            }

            function updateGeolocationDisplay() {
                const container = document.getElementById('geolocation-container');
                if (Object.keys(geolocationData).length === 0) {
                    container.innerHTML = '<p class="text-gray-400 text-sm empty-state">IP geolocations will appear here as they are discovered during simulation.</p>';
                    return;
                }

                let html = '';
                for (const [ip, info] of Object.entries(geolocationData)) {
                    const loc = (info && info.location) ? info.location : info;
                    html += `
                    <div class="geo-item">
                        <span class="geo-ip">${ip}</span>
                        <span class="geo-location">${loc}</span>
                    </div>`;
                }
                container.innerHTML = html;
            }

            function createPacket(startPos, endPos) {
                const packetGeo = new THREE.SphereGeometry(0.2, 12, 12);
                const packetMat = new THREE.MeshBasicMaterial({
                    color: 0x4a9eff,
                    emissive: 0x6bd4ff,
                    emissiveIntensity: 1,
                    transparent: true
                });
                const packet = new THREE.Mesh(packetGeo, packetMat);

                // Add outer glow
                const glowGeo = new THREE.SphereGeometry(0.3, 12, 12);
                const glowMat = new THREE.MeshBasicMaterial({
                    color: 0x6bd4ff,
                    transparent: true,
                    opacity: 0.4,
                    side: THREE.BackSide
                });
                const glow = new THREE.Mesh(glowGeo, glowMat);
                packet.add(glow);

                packet.position.copy(startPos);
                infectionGraphGroup.add(packet);
                animatedObjects.push({ type: 'packet', object: packet, start: startPos.clone(), end: endPos.clone(), progress: 0 });
            }

            function highlightNodeBySignature(data) {
                const pid = data.process_id || data.pid;
                if (!pid) return;
                const nodeToHighlight = nodeMap.get(pid);
                if (nodeToHighlight) animatedObjects.push({ type: 'highlight', object: nodeToHighlight, progress: 0, originalColor: nodeToHighlight.material.color.clone() });
            }

            function animate3D() {
                animationFrameId = requestAnimationFrame(animate3D);
                const delta = clock.getDelta();
                if (!animationStarted) animationStarted = true;
                if (!isPaused) {
                    simulationTime += delta * playbackSpeed;
                    if (nextEventIndex < timelineEvents.length && simulationTime >= timelineEvents[nextEventIndex].time) {
                        const event = timelineEvents[nextEventIndex];
                        const container = document.getElementById('timeline-container');
                        const item = document.createElement('div');
                        item.className = 'timeline-item';
                        let description = '';
                        let locationBadge = '';

                        const timelinePid = event.data.process_id || event.data.pid;
                        const timelinePpid = event.data.parent_id || event.data.ppid;
                        if (event.type === 'process') description = `PID: ${timelinePid}, Parent PID: ${timelinePpid}`;
                        if (event.type === 'dns') description = `Resolves to ${event.data.answers[0]?.data || 'N/A'}`;
                        if (event.type === 'connection') {
                            description = `IP: ${event.data.ip}, Port: ${event.data.port || 'N/A'}`;
                            // Check if we already have geolocation for this IP
                            if (geolocationData[event.data.ip]) {
                                const gd = geolocationData[event.data.ip];
                                locationBadge = `<div class="timeline-location">${gd.location || gd}</div>`;
                            } else {
                                // Store reference to update later when we get the location
                                if (!timelineEventsByIP[event.data.ip]) {
                                    timelineEventsByIP[event.data.ip] = [];
                                }
                                timelineEventsByIP[event.data.ip].push(item);
                                locationBadge = '<div class="timeline-location">Loading location...</div>';
                            }
                        }
                        if (event.type === 'signature') description = event.data.description || 'No details provided.';

                        item.innerHTML = `<div class="timeline-dot"></div><div><h3 class="font-semibold text-white">${event.title}</h3><p class="text-sm text-gray-400 break-words">${description}${locationBadge}</p></div>`;
                        container.prepend(item);
                        setTimeout(() => item.classList.add('active'), 10);
                        trigger3DAnimation(event);

                        // Process Tree logic
                        if (event.type === 'execution') {
                            const ptContainer = document.getElementById('process-tree-container');
                            if (ptContainer.querySelector('.empty-state')) {
                                ptContainer.innerHTML = '<div id="ptree-root"></div>';
                            }
                            const root = document.getElementById('ptree-root');
                            if (root) {
                                root.innerHTML = `
                                    <ul class="min-w-max">
                                        <li id="ptree-initial">
                                            <div class="node-card">
                                                <div class="flex justify-between items-center">
                                                    <div class="flex items-center">
                                                        <i class="fas fa-bug text-red-500 mr-3 text-lg w-5 text-center"></i>
                                                        <span class="font-bold text-white text-base">${event.data.name}</span>
                                                        ${event.data.benign ? '<span class="ml-3 text-xs font-semibold text-green-400 border border-green-400/50 bg-green-400/10 px-2 py-0.5 rounded">Benign</span>' : ''}
                                                    </div>
                                                </div>
                                            </div>
                                        </li>
                                    </ul>
                                `;
                            }
                        } else if (event.type === 'process') {
                            const ptContainer = document.getElementById('process-tree-container');
                            if (ptContainer.querySelector('.empty-state')) {
                                ptContainer.innerHTML = '<div id="ptree-root"></div>';
                            }

                            const ppid = event.data.parent_id || event.data.ppid || 'N/A';
                            const pid = event.data.process_id || event.data.pid || 'N/A';
                            const pName = event.data.process_name || event.data.name;
                            const cmdLine = event.data._cmdLine || '';

                            let parentLi = document.getElementById(`ptree-${ppid}`);
                            if (!parentLi) parentLi = document.getElementById('ptree-initial');
                            if (!parentLi) parentLi = document.getElementById('ptree-root');
                            if (!parentLi) parentLi = ptContainer;

                            let ul = parentLi.querySelector(':scope > ul');
                            if (!ul) {
                                ul = document.createElement('ul');
                                if (parentLi.id === 'ptree-root') ul.className = 'min-w-max';
                                parentLi.appendChild(ul);
                            }

                            const li = document.createElement('li');
                            li.id = `ptree-${pid}`;
                            li.className = 'text-sm mt-1';

                            const cmdHtml = cmdLine ? `<div class="text-xs text-gray-400 mt-2 font-mono whitespace-normal break-all bg-gray-900/50 p-2 rounded border border-gray-700" title="${cmdLine.replace(/"/g, '&quot;')}">${cmdLine}</div>` : '';

                            // Build Stats Badges
                            const stats = event.data._stats || { file: 0, reg: 0, net: 0, sync: 0 };
                            let statsHtml = '<div class="flex flex-wrap gap-2 mt-2">';
                            if (stats.file > 0) statsHtml += `<span class="proc-stats-badge px-1.5 py-0.5 rounded bg-blue-500/20 text-blue-400 text-[10px] font-bold flex items-center gap-1.5 border border-blue-500/30" title="${stats.file} File Operations detected" onclick="showProcActivity(${pid}, 'FILES')"><i class="fas fa-file-alt"></i> FILES: ${stats.file}</span>`;
                            if (stats.reg > 0) statsHtml += `<span class="proc-stats-badge px-1.5 py-0.5 rounded bg-purple-500/20 text-purple-400 text-[10px] font-bold flex items-center gap-1.5 border border-purple-500/30" title="${stats.reg} Registry Operations detected" onclick="showProcActivity(${pid}, 'REGISTRY')"><i class="fas fa-key"></i> REGISTRY: ${stats.reg}</span>`;
                            if (stats.net > 0) statsHtml += `<span class="proc-stats-badge px-1.5 py-0.5 rounded bg-emerald-500/20 text-emerald-400 text-[10px] font-bold flex items-center gap-1.5 border border-emerald-500/30" title="${stats.net} Network Connections detected" onclick="showProcActivity(${pid}, 'NETWORK')"><i class="fas fa-network-wired"></i> NETWORK: ${stats.net}</span>`;
                            if (stats.sync > 0) statsHtml += `<span class="proc-stats-badge px-1.5 py-0.5 rounded bg-amber-500/20 text-amber-400 text-[10px] font-bold flex items-center gap-1.5 border border-amber-500/30" title="${stats.sync} System/Sync calls detected" onclick="showProcActivity(${pid}, 'SYSTEM')"><i class="fas fa-microchip"></i> SYSTEM: ${stats.sync}</span>`;
                            statsHtml += '</div>';

                            const det2pid = reportData.detections2pid || {};
                            const pThreats = det2pid[pid] || [];
                            const threatLabel = pThreats.length > 0 ? `<div class="bg-red-500/10 text-red-400 px-2 py-0.5 rounded border border-red-500/30 animate-pulse font-bold text-[10px] uppercase tracking-wider mt-1 flex items-center gap-1.5"><i class="fas fa-biohazard text-[10px]"></i> ${pThreats.join(', ')}</div>` : '';

                            li.innerHTML = `
                                <div class="node-card">
                                    <div class="flex justify-between items-center gap-6 mb-3">
                                        <div class="flex items-center gap-3">
                                            <i class="fas fa-cog text-gray-500 text-lg w-5 text-center animate-spin-slow"></i>
                                            <div class="flex flex-col">
                                                <span class="font-bold text-white text-base leading-none">${pName}</span>
                                                ${threatLabel}
                                            </div>
                                        </div>
                                        <div class="bg-gray-800/80 px-2 py-1 rounded text-[10px] text-gray-400 border border-gray-700 font-mono flex-shrink-0">PID: ${pid}</div>
                                    </div>
                                    <div class="mt-2">
                                       ${statsHtml}
                                    </div>
                                    ${cmdHtml ? `<div class="mt-2">${cmdHtml}</div>` : ''}
                                </div>
                            `;
                            ul.appendChild(li);

                            // Highlight flash animation
                            li.animate([
                                { backgroundColor: 'rgba(249, 115, 22, 0.4)' },
                                { backgroundColor: 'transparent' }
                            ], { duration: 1500 });

                            // Auto-scroll only if user hasn't scrolled away (within 120px of bottom)
                            const isNearBottom = ptContainer.scrollHeight - ptContainer.scrollTop - ptContainer.clientHeight < 120;
                            if (isNearBottom) {
                                ptContainer.scrollTop = ptContainer.scrollHeight;
                            }
                        }
                        // timeline-synced globe animation: add arcs between sequential connection events
                        // timeline-synced animation: add arcs/lines between sequential connection events
                        if (event.type === 'execution') {
                            lastConnection = null; // reset sequence
                        }
                        if (event.type === 'connection' && event.data && event.data.ip) {
                            const ip = event.data.ip;
                            const info = geolocationData[ip];
                            if (info && info.lat != null && info.lon != null) {
                                const curr = { lat: info.lat, lon: info.lon, ip };
                                // record sequence for persistent polyline
                                connectionSequence.push(ip);
                                rebuildPolyline();
                                if (lastConnection && lastConnection.lat != null) {
                                    // Add animated arc on globe (if available)
                                    if (globeInstance) addTemporaryArc(lastConnection.lat, lastConnection.lon, curr.lat, curr.lon, '#ff6b35', 2800);
                                    // Draw animated 2D connecting line between pins (fallback/visible on 2D map)
                                    draw2DConnection(lastConnection.ip, curr.ip, '#ff6b35', 2800);
                                }
                                lastConnection = curr;
                                // refresh visuals
                                if (globeInstance) refreshGlobeData();
                            }
                        }
                        nextEventIndex++;
                    }
                }

                // Animate particles around all nodes
                infectionGraphGroup.traverse((child) => {
                    if (child.userData && child.userData.particleGroup) {
                        const particleGroup = child.userData.particleGroup;
                        particleGroup.children.forEach((particle) => {
                            if (particle.userData) {
                                const time = clock.getElapsedTime() * particle.userData.speed;
                                const angle = particle.userData.baseAngle + time;
                                particle.position.x = Math.cos(angle) * particle.userData.radius;
                                particle.position.z = Math.sin(angle) * particle.userData.radius;
                                particle.position.y = (Math.sin(time * 2) - 0.5) * particle.userData.radius * 0.5;
                                // Pulsing opacity
                                particle.material.opacity = 0.5 + Math.sin(time * 3) * 0.3;
                            }
                        });
                    }
                });

                // Animate host system glow pulsing
                if (hostSystem && hostSystem.children.length > 0) {
                    const glow = hostSystem.children.find(c => c.material && c.material.opacity < 0.2);
                    if (glow) {
                        const pulse = Math.sin(clock.getElapsedTime() * 1.5) * 0.05 + 0.1;
                        glow.material.opacity = pulse;
                        glow.scale.set(1 + pulse, 1 + pulse, 1 + pulse);
                    }
                }

                for (let i = animatedObjects.length - 1; i >= 0; i--) {
                    const anim = animatedObjects[i];
                    if (!isPaused) anim.progress += delta * playbackSpeed;
                    if (anim.type === 'scaleIn') {
                        const p = Math.min(anim.progress / 0.5, 1);
                        anim.object.scale.set(p, p, p);
                        if (p >= 1) animatedObjects.splice(i, 1);
                    } else if (anim.type === 'fadeIn') {
                        const p = Math.min(anim.progress / 0.5, 1);
                        // Enhanced glowing line effect
                        anim.object.material.opacity = p * 0.8;
                        if (anim.object.userData && anim.object.userData.trail) {
                            anim.object.userData.trail.material.opacity = p * 0.4;
                        }
                        if (p >= 1) animatedObjects.splice(i, 1);
                    } else if (anim.type === 'packet') {
                        const p = Math.min(anim.progress / 1.5, 1);
                        anim.object.position.lerpVectors(anim.start, anim.end, p);
                        // Add glow trail effect to packet
                        const glowIntensity = Math.sin(p * Math.PI);
                        anim.object.material.emissiveIntensity = glowIntensity;
                        if (p >= 1) { infectionGraphGroup.remove(anim.object); animatedObjects.splice(i, 1); }
                    } else if (anim.type === 'highlight') {
                        const p = Math.min(anim.progress / 1, 1);
                        const flash = Math.sin(p * Math.PI);
                        anim.object.material.color.lerpColors(anim.originalColor, new THREE.Color(0xffffff), flash);
                        anim.object.material.emissive.lerpColors(anim.originalColor, new THREE.Color(0xffffff), flash);
                        if (p >= 1) {
                            anim.object.material.color.copy(anim.originalColor);
                            anim.object.material.emissive.copy(anim.originalColor);
                            animatedObjects.splice(i, 1);
                        }
                    }
                }

                if (!isPaused) infectionGraphGroup.rotation.y += 0.002 * playbackSpeed;
                controls.update();
                hostSystem.rotation.y += 0.001;
                renderer.render(scene, camera);
                labelRenderer.render(scene, camera);
                // detect animation end (no more events and no active animations)
                if (!animationEnded && nextEventIndex >= timelineEvents.length && animatedObjects.length === 0) {
                    animationEnded = true;
                    if (pendingView) {
                        const target = pendingView; pendingView = null;
                        performViewSwitch(target);
                    }
                }
            }

            window.handleManualNav = function (action) {
                const currentTab = document.querySelector('.nav-tab.active')?.id.replace('nav-tab-', '');

                if (currentTab === 'map' && leafletMap) {
                    const panStep = 100;
                    switch (action) {
                        case 'up': leafletMap.panBy([0, -panStep]); break;
                        case 'down': leafletMap.panBy([0, panStep]); break;
                        case 'left': leafletMap.panBy([-panStep, 0]); break;
                        case 'right': leafletMap.panBy([panStep, 0]); break;
                        case 'zoomIn': leafletMap.zoomIn(); break;
                        case 'zoomOut': leafletMap.zoomOut(); break;
                        case 'reset': leafletMap.setView([20, 0], 2); break;
                    }
                } else if (currentTab === '3d' && controls) {
                    const panStep = 5;
                    const vector = new THREE.Vector3();
                    
                    switch (action) {
                        case 'up':
                            vector.setFromMatrixColumn(camera.matrix, 1);
                            vector.multiplyScalar(panStep);
                            camera.position.add(vector);
                            controls.target.add(vector);
                            break;
                        case 'down':
                            vector.setFromMatrixColumn(camera.matrix, 1);
                            vector.multiplyScalar(-panStep);
                            camera.position.add(vector);
                            controls.target.add(vector);
                            break;
                        case 'left':
                            vector.setFromMatrixColumn(camera.matrix, 0);
                            vector.multiplyScalar(-panStep);
                            camera.position.add(vector);
                            controls.target.add(vector);
                            break;
                        case 'right':
                            vector.setFromMatrixColumn(camera.matrix, 0);
                            vector.multiplyScalar(panStep);
                            camera.position.add(vector);
                            controls.target.add(vector);
                            break;
                        case 'zoomIn':
                            const dirIn = new THREE.Vector3().subVectors(controls.target, camera.position);
                            camera.position.addScaledVector(dirIn, 0.2);
                            break;
                        case 'zoomOut':
                            const dirOut = new THREE.Vector3().subVectors(camera.position, controls.target);
                            camera.position.addScaledVector(dirOut, 0.2);
                            break;
                        case 'reset':
                            camera.position.set(0, 25, 55);
                            controls.target.set(0, 0, 0);
                            break;
                    }
                    controls.update();
                }
            };
        });

/* GenAI Security Gateway — dashboard interactions.
 *
 * Both panels read from /api/activity, the Flask route that proxies the
 * gateway's /history endpoint. One fetch feeds the audit table and the
 * activity chart. Nothing on this page is synthesised: an empty database
 * produces empty panels, never placeholder rows.
 */

'use strict';

var ACTION_TONE = { Passed: 'ok', Blocked: 'danger' };
var RISK_TONE = { Low: 'ok', Medium: 'warn', High: 'danger' };

/* Newest-first cap on the table. The chart still uses the full window. */
var MAX_AUDIT_ROWS = 25;

/* Rows currently on screen, so the CSV export matches what the user sees. */
var auditRows = [];

function pad2(value) {
    return String(value).padStart(2, '0');
}

/* Explicit 24-hour formatting in local time. toLocaleTimeString() was picking
 * the runtime locale's convention, which yields "05:27:38 PM" under en-US.
 * Building the string by hand avoids both that and the h24 locales that
 * render midnight as "24:00". */
function formatClock(date) {
    return pad2(date.getHours()) + ':' + pad2(date.getMinutes());
}

function formatClockSeconds(date) {
    return formatClock(date) + ':' + pad2(date.getSeconds());
}

/* Full local date-time for the CSV, where a bare clock time loses the day. */
function formatDateTime(date) {
    return date.getFullYear() + '-' + pad2(date.getMonth() + 1) + '-' +
           pad2(date.getDate()) + ' ' + formatClockSeconds(date);
}

function isSameDay(a, b) {
    return a.getFullYear() === b.getFullYear() &&
           a.getMonth() === b.getMonth() &&
           a.getDate() === b.getDate();
}

/* Older-than-today rows carry their date, otherwise a table spanning several
 * days shows bare clock times and a correctly sorted list reads as shuffled. */
function formatAuditTime(date) {
    if (isSameDay(date, new Date())) {
        return formatClockSeconds(date);
    }
    return pad2(date.getMonth() + 1) + '-' + pad2(date.getDate()) + ' ' +
           formatClockSeconds(date);
}

function makeBadge(text, tone) {
    var span = document.createElement('span');
    span.className = 'badge badge-' + tone;
    span.textContent = text;
    return span;
}

function makeCell(text, className) {
    var td = document.createElement('td');
    td.textContent = text;
    if (className) { td.className = className; }
    return td;
}

/* The backend stores a 0-100 risk_score rather than a band, so the label is
 * derived here. Its scorer currently emits 10 (Safe), 80 (DLP Violation) and
 * 95 (Prompt Injection); the Medium band covers scores in between. */
function riskLevel(score) {
    var value = Number(score);
    if (!isFinite(value)) { return 'Unknown'; }
    if (value >= 70) { return 'High'; }
    if (value >= 40) { return 'Medium'; }
    return 'Low';
}

function normalizeAuditRecord(record) {
    var stamp = readTimestamp(record);

    return {
        at: stamp,
        timestamp: stamp ? formatAuditTime(stamp) : '—',
        exportTimestamp: stamp ? formatDateTime(stamp) : '',
        prompt: record.prompt || '—',
        threat: record.threat_type || '—',
        action: isBlockedRecord(record) ? 'Blocked' : 'Passed',
        risk: riskLevel(record.risk_score)
    };
}

function renderEmptyRow(body, message) {
    var tr = document.createElement('tr');
    var td = document.createElement('td');
    td.className = 'table-empty';
    td.colSpan = 5;
    td.textContent = message;
    tr.appendChild(td);
    body.appendChild(tr);
}

/* Builds rows via textContent rather than innerHTML — prompts are
 * attacker-controlled by definition, so they must never be parsed as markup. */
function renderAuditLogs(rows) {
    var body = document.getElementById('auditBody');
    if (!body) { return; }

    body.textContent = '';
    auditRows = rows;

    var exportBtn = document.getElementById('exportBtn');
    if (exportBtn) { exportBtn.disabled = !rows.length; }

    if (!rows.length) {
        renderEmptyRow(body, 'No requests logged in this window.');
        return;
    }

    rows.forEach(function (row) {
        var tr = document.createElement('tr');

        tr.appendChild(makeCell(row.timestamp, 'col-time'));
        tr.appendChild(makeCell(row.prompt, 'col-snippet'));
        tr.appendChild(makeCell(row.threat, 'col-threat'));

        var actionCell = document.createElement('td');
        actionCell.appendChild(makeBadge(row.action, ACTION_TONE[row.action] || 'neutral'));
        tr.appendChild(actionCell);

        var riskCell = document.createElement('td');
        riskCell.appendChild(makeBadge(row.risk, RISK_TONE[row.risk] || 'neutral'));
        tr.appendChild(riskCell);

        body.appendChild(tr);
    });
}

function showAuditError(message) {
    var body = document.getElementById('auditBody');
    if (!body) { return; }

    auditRows = [];
    body.textContent = '';
    renderEmptyRow(body, message);

    var exportBtn = document.getElementById('exportBtn');
    if (exportBtn) { exportBtn.disabled = true; }
}

/* CSV rather than a real .xlsx — Excel opens it natively and it needs no
 * backend or third-party library. The BOM keeps Excel in UTF-8. */
function toCsv(rows) {
    var header = ['Timestamp', 'Prompt', 'Threat Type', 'Action Taken', 'Risk Level'];

    var escape = function (value) {
        return '"' + String(value).replace(/"/g, '""') + '"';
    };

    var lines = [header.map(escape).join(',')];

    rows.forEach(function (row) {
        lines.push([
            row.exportTimestamp,
            row.prompt,
            row.threat,
            row.action,
            row.risk
        ].map(escape).join(','));
    });

    return '\ufeff' + lines.join('\r\n');
}

function exportToExcel(rows) {
    var blob = new Blob([toCsv(rows)], { type: 'text/csv;charset=utf-8;' });
    var url = URL.createObjectURL(blob);
    var stamp = new Date().toISOString().slice(0, 10);

    var link = document.createElement('a');
    link.href = url;
    link.download = 'audit-logs-' + stamp + '.csv';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    URL.revokeObjectURL(url);
}

/* ------------------------------------------------------------------
 * Activity trends
 *
 * Every label below is derived from a real timestamp in the API payload.
 * Nothing here invents an hour, and no bucket exists unless the data
 * covers it — if the endpoint returns nothing, the empty state stays up.
 * ------------------------------------------------------------------ */

/* Same-origin: the browser cannot resolve the Docker-internal hostname the
 * server-side call uses, so this needs a Flask route that proxies the
 * gateway. No such route exists yet — the fetch 404s until one is added. */
var ACTIVITY_ENDPOINT = '/api/activity';
var BUCKET_MINUTES = 60;

var activityChartInstance = null;

/* Accepts ISO-8601 strings, epoch seconds, or epoch milliseconds. */
function toDate(value) {
    if (value instanceof Date) {
        return isNaN(value.getTime()) ? null : value;
    }

    if (typeof value === 'number') {
        /* Anything below ~1973 in ms is far likelier to be epoch seconds. */
        var ms = value < 1e11 ? value * 1000 : value;
        var fromNumber = new Date(ms);
        return isNaN(fromNumber.getTime()) ? null : fromNumber;
    }

    if (typeof value === 'string') {
        var parsed = new Date(value);
        return isNaN(parsed.getTime()) ? null : parsed;
    }

    return null;
}

function readTimestamp(record) {
    return toDate(record.timestamp || record.time || record.created_at || record.ts);
}

function isBlockedRecord(record) {
    if (typeof record.blocked === 'boolean') { return record.blocked; }
    if (typeof record.action === 'string') {
        return record.action.trim().toLowerCase() === 'blocked';
    }
    return false;
}

/* Floors in local time rather than on the epoch, so buckets line up with the
 * wall clock in zones with sub-hour UTC offsets (e.g. UTC+05:30). */
function floorToBucket(date, bucketMinutes) {
    var floored = new Date(date.getTime());
    floored.setSeconds(0, 0);
    floored.setMinutes(Math.floor(floored.getMinutes() / bucketMinutes) * bucketMinutes);
    return floored;
}

/* Groups raw per-request records into time buckets spanning only the range
 * the data actually covers. Interior gaps are filled with zeroes because a
 * bucket with no records genuinely saw no traffic — that is measured, not
 * assumed. The span never extends past the newest or oldest real record. */
function bucketActivity(records, bucketMinutes) {
    var counts = {};
    var earliest = null;
    var latest = null;

    records.forEach(function (record) {
        var stamp = readTimestamp(record);
        if (!stamp) { return; }

        var bucket = floorToBucket(stamp, bucketMinutes);
        var key = bucket.getTime();

        if (!counts[key]) { counts[key] = { requests: 0, blocked: 0 }; }
        counts[key].requests += 1;
        if (isBlockedRecord(record)) { counts[key].blocked += 1; }

        if (earliest === null || key < earliest) { earliest = key; }
        if (latest === null || key > latest) { latest = key; }
    });

    if (earliest === null) { return []; }

    var series = [];
    var step = bucketMinutes * 60000;

    for (var key = earliest; key <= latest; key += step) {
        var slot = counts[key] || { requests: 0, blocked: 0 };
        series.push({
            label: formatClock(new Date(key)),
            requests: slot.requests,
            blocked: slot.blocked
        });
    }

    return series;
}

/* Handles both payload shapes: a pre-aggregated series from the backend, or
 * raw records this bucket client-side. Pre-aggregated data is passed through
 * without gap-filling — only the source knows whether a gap means zero. */
function buildSeries(payload) {
    var records = payload;

    if (payload && !Array.isArray(payload)) {
        records = payload.data || payload.records || payload.results || payload.items;
    }

    if (!Array.isArray(records) || !records.length) { return []; }

    var preAggregated = typeof records[0].requests === 'number';

    if (!preAggregated) {
        return bucketActivity(records, BUCKET_MINUTES);
    }

    return records
        .map(function (point) {
            return { point: point, at: readTimestamp(point) };
        })
        .filter(function (entry) { return entry.at !== null; })
        .sort(function (a, b) { return a.at - b.at; })
        .map(function (entry) {
            return {
                label: formatClock(entry.at),
                requests: Number(entry.point.requests) || 0,
                blocked: Number(entry.point.blocked || entry.point.blocked_threats) || 0
            };
        });
}

function setChartMessage(title, note) {
    var titleEl = document.querySelector('#chartEmpty .chart-empty-title');
    var noteEl = document.querySelector('#chartEmpty .chart-empty-note');
    if (titleEl) { titleEl.textContent = title; }
    if (noteEl) { noteEl.textContent = note; }
}

function fetchHistory() {
    return fetch(ACTIVITY_ENDPOINT, { headers: { Accept: 'application/json' } })
        .then(function (response) {
            if (!response.ok) {
                throw new Error('Activity endpoint returned HTTP ' + response.status);
            }
            return response.json();
        });
}

function extractRecords(payload) {
    if (Array.isArray(payload)) { return payload; }
    if (!payload) { return []; }

    var records = payload.records || payload.data || payload.results || payload.items;
    return Array.isArray(records) ? records : [];
}

/* One request serves both panels — the table takes the newest slice, the
 * chart buckets the whole window. */
function loadDashboardData() {
    fetchHistory()
        .then(function (payload) {
            var records = extractRecords(payload);

            renderAuditLogs(
                records
                    .map(normalizeAuditRecord)
                    .filter(function (row) { return row.at !== null; })
                    .sort(function (a, b) { return b.at - a.at; })
                    .slice(0, MAX_AUDIT_ROWS)
            );

            if (typeof Chart === 'undefined') {
                setChartMessage('Chart library unavailable',
                    'Chart.js failed to load, so the activity graph cannot be drawn.');
                return;
            }

            var series = buildSeries(payload);

            if (!series.length) {
                setChartMessage('No activity recorded yet',
                    'The gateway has not logged any requests in this window.');
                return;
            }

            renderActivityChart(series);
        })
        .catch(function (error) {
            showAuditError('Could not load audit logs — ' + error.message);
            setChartMessage('Activity history unavailable',
                'Could not load ' + ACTIVITY_ENDPOINT + ' — ' + error.message +
                '. The chart stays empty rather than showing invented figures.');
        });
}

/* Draws the chart from { label, requests, blocked } points. */
function renderActivityChart(series) {
    var canvas = document.getElementById('activityChart');
    var empty = document.getElementById('chartEmpty');

    if (!canvas || typeof Chart === 'undefined' || !series || !series.length) {
        return false;
    }

    canvas.hidden = false;
    if (empty) { empty.hidden = true; }

    if (activityChartInstance) { activityChartInstance.destroy(); }

    activityChartInstance = new Chart(canvas.getContext('2d'), {
        type: 'line',
        data: {
            labels: series.map(function (p) { return p.label; }),
            datasets: [
                {
                    label: 'Requests',
                    data: series.map(function (p) { return p.requests; }),
                    borderColor: '#5b9dff',
                    backgroundColor: 'rgba(91, 157, 255, 0.14)',
                    tension: 0.35,
                    fill: true
                },
                {
                    label: 'Blocked threats',
                    data: series.map(function (p) { return p.blocked; }),
                    borderColor: '#f8717f',
                    backgroundColor: 'rgba(248, 113, 127, 0.14)',
                    tension: 0.35,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { labels: { color: '#8b97ad', boxWidth: 12 } } },
            scales: {
                x: { ticks: { color: '#8b97ad' }, grid: { color: 'rgba(255,255,255,0.06)' } },
                y: {
                    beginAtZero: true,
                    /* Counts are whole requests — no fractional gridlines. */
                    ticks: { color: '#8b97ad', precision: 0 },
                    grid: { color: 'rgba(255,255,255,0.06)' }
                }
            }
        }
    });

    return true;
}

document.addEventListener('DOMContentLoaded', function () {
    var exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
        /* Re-enabled by renderAuditLogs() once real rows arrive. */
        exportBtn.disabled = true;
        exportBtn.addEventListener('click', function () {
            if (auditRows.length) { exportToExcel(auditRows); }
        });
    }

    loadDashboardData();
});

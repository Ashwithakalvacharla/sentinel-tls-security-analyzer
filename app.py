import html
import ipaddress
import json
import socket
import sqlite3
import ssl
from datetime import datetime, timezone
from io import BytesIO
from urllib.parse import urlsplit

import streamlit as st

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# ---------------- CONFIGURATION ----------------
DB_PATH = "tls_scan_history.db"
TIMEOUT_SECONDS = 8

st.set_page_config(
    page_title="Sentinel | TLS Security Analyzer",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ---------------- DESIGN ----------------
st.markdown(
    """
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');
    .stApp {background:#080d18;color:#e6edf7;font-family:'Inter',sans-serif;}
    .block-container {max-width:1250px;padding-top:2rem;padding-bottom:3rem;}
    header[data-testid="stHeader"] {background:transparent;}
    .hero {background:linear-gradient(125deg,#111d34,#102d3a 70%,#102238);border:1px solid #243d53;border-radius:24px;padding:32px;margin:14px 0 26px;}
    .eyebrow {color:#43e0c0;font-size:12px;letter-spacing:2px;font-weight:800;text-transform:uppercase;}
    .hero h1 {color:#f5f8ff;font-size:clamp(28px,4vw,43px);line-height:1.2;margin:13px 0;font-weight:800;}
    .hero p {color:#a9bbd2;font-size:15px;line-height:1.8;max-width:760px;}
    .section-title {color:#f1f6ff;font-size:21px;font-weight:800;margin:22px 0 15px;}
    .metric {background:linear-gradient(145deg,#111e31,#0d1727);border:1px solid #273951;border-radius:17px;padding:20px;min-height:125px;margin-bottom:12px;}
    .metric-label {color:#9cafc8;font-size:12px;text-transform:uppercase;letter-spacing:1px;font-weight:700;}
    .metric-value {color:#f2f7ff;font-size:24px;font-weight:800;margin-top:14px;overflow-wrap:anywhere;}
    .metric-note {color:#9fb5cf;font-size:12px;margin-top:7px;}
    .field-label {color:#a7bad2;font-size:12px;margin-bottom:4px;text-transform:uppercase;letter-spacing:.5px;}
    .field-value {color:#edf4ff;font-size:14px;font-weight:600;overflow-wrap:anywhere;line-height:1.7;margin-bottom:13px;}
    .finding {background:#121f31;border:1px solid #2a3c53;border-radius:12px;padding:14px;margin:9px 0;color:#dce8f7;line-height:1.6;}
    .good {border-left:4px solid #37d6aa;}.warning {border-left:4px solid #ffbd59;}.bad {border-left:4px solid #ff6b81;}
    .score {font-size:42px;font-weight:800;line-height:1.15;}
    .footer {color:#6f829c;font-size:12px;text-align:center;padding:25px 0 5px;}
    .stButton > button {background:linear-gradient(100deg,#21cbb0,#27a8e8);color:#06131f;border:none;border-radius:11px;min-height:46px;font-weight:800;width:100%;}
    .stButton > button:hover {background:linear-gradient(100deg,#55e6c9,#59c5f4);color:#06131f;border:none;}
    .stDownloadButton > button {background:#183047 !important;color:#f1f7ff !important;border:1px solid #3b607c !important;border-radius:10px !important;font-weight:700 !important;min-height:44px;}
    .stTextInput input {background:#0b1423;border:1px solid #30445e;color:#f1f6ff;border-radius:10px;min-height:46px;}
    div[data-testid="stAlert"] {border-radius:12px;} hr {border-color:#26354b;}
    </style>
    """,
    unsafe_allow_html=True,
)

# ---------------- DATABASE ----------------
def init_db():
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                score INTEGER NOT NULL,
                score_label TEXT NOT NULL,
                status TEXT NOT NULL,
                days_remaining INTEGER NOT NULL,
                tls_version TEXT NOT NULL,
                result_json TEXT NOT NULL,
                findings_json TEXT NOT NULL
            )"""
        )
        conn.commit()


def save_scan(result, score, score_label, findings):
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute(
            """INSERT INTO scans
            (domain, scanned_at, score, score_label, status, days_remaining,
             tls_version, result_json, findings_json)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                result["domain"], result["scanned_at"], score, score_label,
                result["status"], result["days_remaining"], result["tls_version"],
                json.dumps(result), json.dumps(findings),
            ),
        )
        conn.commit()


def get_history(domain=None, limit=100):
    with sqlite3.connect(DB_PATH) as conn:
        conn.row_factory = sqlite3.Row
        if domain:
            rows = conn.execute(
                "SELECT * FROM scans WHERE domain = ? ORDER BY id DESC LIMIT ?",
                (domain, limit),
            ).fetchall()
        else:
            rows = conn.execute(
                "SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
    return [dict(row) for row in rows]


init_db()

# ---------------- DOMAIN VALIDATION ----------------
def validate_domain(raw):
    value = raw.strip()
    if not value:
        raise ValueError("Enter a website domain, for example google.com.")
    if "://" not in value:
        value = "https://" + value

    parsed = urlsplit(value)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS websites are supported. Enter a domain or https:// URL.")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Enter a valid website hostname.")
    try:
        if parsed.port not in (None, 443):
            raise ValueError("Only port 443 is supported.")
    except ValueError as exc:
        raise ValueError("Invalid port. Only port 443 is supported.") from exc
    if parsed.path not in ("", "/") or parsed.query or parsed.fragment:
        raise ValueError("Enter only the domain, without a path, query, or fragment.")

    host = parsed.hostname.rstrip(".").lower()
    if host == "localhost" or host.endswith(".localhost"):
        raise ValueError("Localhost is not allowed.")
    try:
        ip = ipaddress.ip_address(host)
        if not ip.is_global:
            raise ValueError("Private or reserved IP addresses are blocked.")
    except ValueError as exc:
        if "Private or reserved" in str(exc):
            raise
        labels = host.split(".")
        if len(labels) < 2 or not all(
            label and len(label) <= 63 and label[0].isalnum()
            and label[-1].isalnum()
            and all(ch.isalnum() or ch == "-" for ch in label)
            for label in labels
        ):
            raise ValueError("Enter a valid domain name.")
    return host


# ---------------- TLS CONNECTION AND ANALYSIS ----------------
def resolve_public_addresses(host):
    try:
        addresses = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise
    public_addresses = []
    for item in addresses:
        address = item[4][0]
        ip = ipaddress.ip_address(address)
        if not ip.is_global:
            raise ValueError("The domain resolves to a private or reserved address; scan blocked.")
        public_addresses.append(item)
    if not public_addresses:
        raise OSError("No usable public IP address was found.")
    return public_addresses


def connect_tls(host, addresses, min_version=None, max_version=None):
    last_error = None
    for family, socktype, proto, _, sockaddr in addresses:
        raw_socket = socket.socket(family, socktype, proto)
        raw_socket.settimeout(TIMEOUT_SECONDS)
        try:
            raw_socket.connect(sockaddr)
            context = ssl.create_default_context()
            if min_version is not None:
                context.minimum_version = min_version
            if max_version is not None:
                context.maximum_version = max_version
            tls_socket = context.wrap_socket(raw_socket, server_hostname=host)
            return tls_socket
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            raw_socket.close()
    if last_error:
        raise last_error
    raise OSError("Could not establish a TLS connection.")


def test_tls_protocol(host, addresses, version):
    """Try a single TLS version with certificate verification still enabled."""
    try:
        if version == "TLS 1.2":
            sock = connect_tls(host, addresses, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2)
        elif version == "TLS 1.3":
            if not hasattr(ssl.TLSVersion, "TLSv1_3"):
                return {"protocol": version, "supported": False, "detail": "Not supported by this Python/OpenSSL build."}
            sock = connect_tls(host, addresses, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3)
        else:
            return {"protocol": version, "supported": False, "detail": "Unsupported test version."}
        with sock:
            negotiated = sock.version() or version
        return {"protocol": version, "supported": True, "detail": f"Handshake succeeded; negotiated {negotiated}."}
    except ssl.SSLCertVerificationError as exc:
        return {"protocol": version, "supported": None, "detail": f"Certificate verification failed during test: {getattr(exc, 'verify_message', str(exc))}"}
    except (ssl.SSLError, OSError, socket.timeout) as exc:
        return {"protocol": version, "supported": False, "detail": f"Handshake did not succeed: {exc}"}


def scan_tls(host):
    addresses = resolve_public_addresses(host)
    tls = connect_tls(host, addresses)
    with tls:
        cert = tls.getpeercert()
        cipher_info = tls.cipher()
        now = datetime.now(timezone.utc)
        not_before = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), tz=timezone.utc)
        not_after = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), tz=timezone.utc)
        remaining_seconds = (not_after - now).total_seconds()
        days_remaining = int(remaining_seconds // 86400)

        if now < not_before:
            status = "NOT YET VALID"
        elif now > not_after:
            status = "EXPIRED"
        elif remaining_seconds <= 7 * 86400:
            status = "EXPIRING WITHIN 7 DAYS"
        elif remaining_seconds <= 30 * 86400:
            status = "EXPIRING SOON"
        else:
            status = "VALID"

        subject = ", ".join(f"{key}={value}" for group in cert.get("subject", []) for key, value in group)
        issuer = ", ".join(f"{key}={value}" for group in cert.get("issuer", []) for key, value in group)
        sans = [value for kind, value in cert.get("subjectAltName", []) if kind in ("DNS", "IP Address")]
        result = {
            "domain": host,
            "scanned_at": now.strftime("%Y-%m-%d %H:%M:%S UTC"),
            "connection": "SUCCESS",
            "verification": "PASSED",
            "hostname": "PASSED",
            "tls_version": tls.version() or "Unknown",
            "cipher": cipher_info[0] if cipher_info else "Unknown",
            "cipher_protocol": cipher_info[1] if cipher_info else "Unknown",
            "cipher_bits": cipher_info[2] if cipher_info else None,
            "subject": subject or "Not available",
            "issuer": issuer or "Not available",
            "valid_from": not_before.strftime("%Y-%m-%d %H:%M UTC"),
            "valid_until": not_after.strftime("%Y-%m-%d %H:%M UTC"),
            "days_remaining": days_remaining,
            "status": status,
            "serial_number": cert.get("serialNumber", "Not available"),
            "sans": sans,
        }

    # Explicitly test TLS 1.2 and 1.3 separately; this is not a full cipher scan.
    result["protocol_tests"] = [
        test_tls_protocol(host, addresses, "TLS 1.2"),
        test_tls_protocol(host, addresses, "TLS 1.3"),
    ]
    return result


# ---------------- SCORE AND FINDINGS ----------------
def calculate_security_score(result):
    score = 100
    findings = []
    status = result.get("status", "UNKNOWN")
    days = result.get("days_remaining", -1)
    tls_version = result.get("tls_version", "Unknown")
    cipher = result.get("cipher", "Unknown")

    if status == "EXPIRED" or days < 0:
        score -= 60
        findings.append(("bad", "CRITICAL", "Certificate expired. Renew it immediately."))
    elif status == "NOT YET VALID":
        score -= 40
        findings.append(("bad", "HIGH", "Certificate is not yet valid. Check certificate dates and system clock."))
    elif days <= 7:
        score -= 25
        findings.append(("bad", "HIGH", "Certificate expires within 7 days. Renew it as soon as possible."))
    elif days <= 30:
        score -= 15
        findings.append(("warning", "MEDIUM", "Certificate expires within 30 days. Plan renewal."))
    else:
        findings.append(("good", "PASS", "Certificate is within its validity period."))

    if result.get("hostname") != "PASSED":
        score -= 30
        findings.append(("bad", "HIGH", "Hostname verification did not pass. Configure a matching certificate."))
    else:
        findings.append(("good", "PASS", "Hostname verification passed."))

    if result.get("verification") != "PASSED":
        score -= 40
        findings.append(("bad", "HIGH", "Certificate chain verification did not pass."))
    else:
        findings.append(("good", "PASS", "Certificate chain verification passed."))

    if tls_version in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2"):
        score -= 25
        findings.append(("bad", "HIGH", f"Outdated negotiated protocol: {tls_version}. Disable obsolete protocol versions."))
    else:
        findings.append(("good", "INFO", f"Negotiated protocol: {tls_version}. Separate TLS 1.2/1.3 tests are listed below."))

    cipher_upper = cipher.upper()
    if cipher == "Unknown":
        score -= 10
        findings.append(("warning", "MEDIUM", "Cipher-suite information was unavailable."))
    elif any(weak in cipher_upper for weak in ("RC4", "3DES", "DES-CBC", "NULL", "EXPORT", "MD5")):
        score -= 20
        findings.append(("bad", "HIGH", f"Potentially weak cipher name detected: {cipher}. Review server TLS configuration."))
    else:
        findings.append(("good", "INFO", f"Negotiated cipher suite: {cipher}. Name-based checks are not a complete cryptographic audit."))

    score = max(0, min(100, score))
    label = "Strong" if score >= 85 else "Moderate" if score >= 65 else "Needs attention"
    return score, label, findings


def explain_tls_error(exc):
    reason = getattr(exc, "verify_message", "") or str(exc)
    lower = reason.lower()
    if "expired" in lower:
        return "Certificate expired: the server's certificate is no longer valid. The website administrator should renew it."
    if "hostname" in lower or "doesn't match" in lower or "not valid for" in lower:
        return "Hostname mismatch: the certificate does not match the domain entered. Configure a certificate for this hostname."
    if "self-signed" in lower:
        return "Untrusted certificate: the server presented a self-signed certificate that the system does not trust."
    if "not yet valid" in lower:
        return "Certificate is not yet valid. Check the certificate dates and the computer's clock."
    return f"Certificate verification failed: {reason}"


# ---------------- PDF REPORT ----------------
def make_pdf_report(result, score, score_label, findings):
    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("PDF support is not installed. Run: python -m pip install reportlab")
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=18*mm, leftMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm)
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="SmallWrap", parent=styles["BodyText"], fontSize=8, leading=10, wordWrap="CJK"))
    story = [Paragraph("Sentinel TLS Security Assessment", styles["Title"]), Spacer(1, 6*mm)]
    story.append(Paragraph(f"Domain: {html.escape(result['domain'])}", styles["Heading2"]))
    story.append(Paragraph(f"Scanned at: {html.escape(result['scanned_at'])}", styles["BodyText"]))
    story.append(Paragraph(f"Educational security score: {score}/100 ({html.escape(score_label)})", styles["Heading3"]))
    story.append(Spacer(1, 4*mm))
    rows = [["Field", "Value"], ["Certificate status", result["status"]], ["Days remaining", str(result["days_remaining"])], ["TLS version negotiated", result["tls_version"]], ["Cipher suite", result["cipher"]], ["Issuer", result["issuer"]], ["Subject", result["subject"]], ["Valid from", result["valid_from"]], ["Valid until", result["valid_until"]], ["Hostname verification", result["hostname"]], ["Serial number", result["serial_number"]]]
    table = Table([[Paragraph(html.escape(str(cell)), styles["SmallWrap"]) for cell in row] for row in rows], colWidths=[48*mm, 118*mm], repeatRows=1)
    table.setStyle(TableStyle([("BACKGROUND", (0,0), (-1,0), colors.HexColor("#17334b")), ("TEXTCOLOR", (0,0), (-1,0), colors.white), ("GRID", (0,0), (-1,-1), 0.4, colors.grey), ("VALIGN", (0,0), (-1,-1), "TOP"), ("BACKGROUND", (0,1), (-1,-1), colors.whitesmoke), ("PADDING", (0,0), (-1,-1), 6)]))
    story.extend([table, Spacer(1, 6*mm), Paragraph("Security findings", styles["Heading2"])])
    for _, severity, message in findings:
        story.append(Paragraph(f"<b>{html.escape(severity)}:</b> {html.escape(message)}", styles["BodyText"]))
        story.append(Spacer(1, 2*mm))
    story.extend([Spacer(1, 4*mm), Paragraph("TLS protocol compatibility checks", styles["Heading2"])])
    for test in result.get("protocol_tests", []):
        state = "Handshake succeeded" if test["supported"] is True else "Not confirmed" if test["supported"] is None else "Handshake did not succeed"
        story.append(Paragraph(f"<b>{html.escape(test['protocol'])}:</b> {html.escape(state)} — {html.escape(test['detail'])}", styles["BodyText"]))
        story.append(Spacer(1, 2*mm))
    story.append(Spacer(1, 5*mm))
    story.append(Paragraph("Limitations: This educational tool tests the negotiated connection and attempts TLS 1.2/TLS 1.3 handshakes. It is not a full vulnerability audit, does not exhaustively test cipher suites, and a valid certificate does not guarantee that the whole website is safe.", styles["SmallWrap"]))
    doc.build(story)
    return buffer.getvalue()


# ---------------- HEADER ----------------
st.markdown(
    """
    <div class="hero">
      <div class="eyebrow">● CYBERSECURITY · WEB INSPECTION</div>
      <h1>HTTPS &amp; TLS<br>Certificate Analyzer</h1>
      <p>Inspect certificate validity, estimate TLS configuration risk, test TLS 1.2 and TLS 1.3 compatibility, save scan history, and export security reports.</p>
      <div style="color:#8ba7c4;font-size:12px;margin-top:20px;">CERTIFICATE HEALTH &nbsp; / &nbsp; TLS MONITORING &nbsp; / &nbsp; SECURITY REPORTING</div>
    </div>
    """,
    unsafe_allow_html=True,
)

# ---------------- SCAN FORM ----------------
st.markdown('<div class="section-title">⌕ &nbsp; Scan a website</div>', unsafe_allow_html=True)
left, right = st.columns([4, 1], vertical_alignment="bottom")
with left:
    domain_input = st.text_input("Website domain", placeholder="e.g. google.com", label_visibility="collapsed", key="domain_input")
with right:
    scan_clicked = st.button("🔍 Analyze Website", use_container_width=True)
st.caption("Only public hostnames are accepted. The scanner uses verified TLS connections on port 443.")

if scan_clicked:
    st.session_state["scan_result"] = None
    st.session_state["scan_error"] = None
    try:
        host = validate_domain(domain_input)
        with st.spinner(f"Establishing a verified TLS connection to {host}..."):
            result = scan_tls(host)
        score, score_label, findings = calculate_security_score(result)
        save_scan(result, score, score_label, findings)
        st.session_state["scan_result"] = result
        st.session_state["scan_score"] = score
        st.session_state["scan_score_label"] = score_label
        st.session_state["scan_findings"] = findings
    except ValueError as exc:
        st.session_state["scan_error"] = str(exc)
    except ssl.SSLCertVerificationError as exc:
        st.session_state["scan_error"] = explain_tls_error(exc)
    except socket.timeout:
        st.session_state["scan_error"] = "Connection timed out. The server may be slow, unreachable, or blocking the connection. Try again later."
    except socket.gaierror:
        st.session_state["scan_error"] = "The domain could not be resolved. Check the spelling and your internet connection."
    except ssl.SSLError as exc:
        st.session_state["scan_error"] = f"TLS handshake failed: {exc}. The certificate or TLS configuration may not be compatible."
    except OSError as exc:
        st.session_state["scan_error"] = f"Connection failed: {exc}. Check whether the website is reachable on port 443."
    except Exception as exc:
        st.session_state["scan_error"] = f"Unexpected scan error ({type(exc).__name__}): {exc}"

result = st.session_state.get("scan_result")
error = st.session_state.get("scan_error")

if error:
    st.markdown('<div class="section-title">⚠ &nbsp; Scan result</div>', unsafe_allow_html=True)
    st.error(error)
    st.info("Try google.com for a typical valid certificate, or expired.badssl.com / wrong.host.badssl.com to test certificate-verification errors.")

if result:
    score = st.session_state.get("scan_score", 0)
    score_label = st.session_state.get("scan_score_label", "Unknown")
    findings = st.session_state.get("scan_findings", [])
    status = result["status"]
    st.markdown('<div class="section-title">◈ &nbsp; Security overview</div>', unsafe_allow_html=True)
    if status == "VALID":
        st.success("Certificate validation succeeded for this connection. This is not a complete website security audit.")
    elif status == "EXPIRING SOON":
        st.warning("Certificate expires within 30 days. Schedule renewal soon.")
    elif status == "EXPIRING WITHIN 7 DAYS":
        st.error("Certificate expires within 7 days. Renew it as soon as possible.")
    else:
        st.error(f"Certificate status: {status}")

    score_color = "#37d6aa" if score >= 85 else "#ffbd59" if score >= 65 else "#ff6b81"
    c_score, c1, c2, c3, c4 = st.columns([1.15, 1, 1, 1, 1])
    with c_score:
        st.markdown(f'<div class="metric"><div class="metric-label">TLS Score</div><div class="score" style="color:{score_color}">{score}<span style="font-size:17px">/100</span></div><div class="metric-note">{html.escape(score_label)}</div></div>', unsafe_allow_html=True)
    def metric(label, value, note):
        return f'<div class="metric"><div class="metric-label">{html.escape(str(label))}</div><div class="metric-value">{html.escape(str(value))}</div><div class="metric-note">{html.escape(str(note))}</div></div>'
    with c1:
        st.markdown(metric("Connection", "VERIFIED", "TLS handshake succeeded"), unsafe_allow_html=True)
    with c2:
        st.markdown(metric("Certificate", status, "Validity status"), unsafe_allow_html=True)
    with c3:
        st.markdown(metric("Protocol", result["tls_version"], "Negotiated version"), unsafe_allow_html=True)
    with c4:
        st.markdown(metric("Expires in", f'{result["days_remaining"]} days', "Certificate lifetime"), unsafe_allow_html=True)
    st.caption("The score is an educational heuristic, not an industry-standard rating. TLS protocol tests below attempt TLS 1.2 and TLS 1.3 separately.")

    st.markdown('<div class="section-title">▤ &nbsp; Certificate information</div>', unsafe_allow_html=True)
    left_panel, right_panel = st.columns(2)
    def show_field(label, value):
        st.markdown(f'<div class="field-label">{html.escape(str(label))}</div><div class="field-value">{html.escape(str(value))}</div>', unsafe_allow_html=True)
    with left_panel:
        with st.container(border=True):
            show_field("Website", result["domain"])
            show_field("Issuer", result["issuer"])
            show_field("Valid from", result["valid_from"])
            show_field("Serial number", result["serial_number"])
    with right_panel:
        with st.container(border=True):
            show_field("Subject", result["subject"])
            show_field("Valid until", result["valid_until"])
            show_field("Hostname verification", result["hostname"])
            show_field("Cipher suite", f'{result["cipher"]} ({result.get("cipher_bits")} bits)' if result.get("cipher_bits") else result["cipher"])

    st.markdown('<div class="section-title">◈ &nbsp; TLS protocol compatibility</div>', unsafe_allow_html=True)
    st.caption("Each test attempts a separate verified handshake constrained to one protocol version. A failed handshake does not always prove the server itself lacks support; network policy or local TLS libraries can affect the result.")
    protocol_cols = st.columns(2)
    for index, test in enumerate(result.get("protocol_tests", [])):
        with protocol_cols[index % 2]:
            if test["supported"] is True:
                st.success(f'{test["protocol"]}: handshake succeeded')
            elif test["supported"] is False:
                st.warning(f'{test["protocol"]}: handshake did not succeed')
            else:
                st.info(f'{test["protocol"]}: inconclusive')
            st.caption(test["detail"])

    st.markdown('<div class="section-title">◉ &nbsp; Security findings</div>', unsafe_allow_html=True)
    for style, severity, message in findings:
        st.markdown(f'<div class="finding {style}"><b>{html.escape(severity)}:</b> {html.escape(message)}</div>', unsafe_allow_html=True)

    with st.expander("View Subject Alternative Names (SAN)"):
        if result["sans"]:
            for san in result["sans"]:
                st.write("•", san)
        else:
            st.write("No SAN entries were returned in the certificate details.")

    st.caption(f'Last scanned: {result["scanned_at"]}')
    report = {
        **result,
        "security_score": score,
        "score_label": score_label,
        "findings": [{"severity": severity, "message": message} for _, severity, message in findings],
        "limitations": [
            "The score is an educational heuristic, not an industry-standard security rating.",
            "TLS 1.2 and TLS 1.3 are tested separately, but cipher suites are not exhaustively enumerated.",
            "A valid certificate does not guarantee complete website security.",
            "No HTTP-header, application vulnerability, or full penetration test is performed.",
        ],
    }
    st.download_button("⬇ Download Security Report (JSON)", data=json.dumps(report, indent=2), file_name=f'{result["domain"]}_tls_report.json', mime="application/json", use_container_width=True)
    if REPORTLAB_AVAILABLE:
        try:
            pdf_bytes = make_pdf_report(result, score, score_label, findings)
            st.download_button("⬇ Download Security Report (PDF)", data=pdf_bytes, file_name=f'{result["domain"]}_tls_report.pdf', mime="application/pdf", use_container_width=True)
        except Exception as exc:
            st.warning(f"Could not create PDF report: {exc}")
    else:
        st.info("For PDF report downloads, install the reportlab dependency listed in requirements.txt.")

# ---------------- CERTIFICATE MONITORING SUMMARY ----------------
st.markdown('<div class="section-title">🔔 &nbsp; Certificate expiry monitoring</div>', unsafe_allow_html=True)
history = get_history(limit=500)
if not history:
    st.info("Your monitored-domain list will populate after you scan and save domains. Expiry checks run when you scan; this app does not run unattended background scans.")
else:
    latest_by_domain = {}
    for row in reversed(history):
        latest_by_domain[row["domain"]] = row
    expiring = [row for row in latest_by_domain.values() if row["days_remaining"] <= 30]
    if expiring:
        for row in sorted(expiring, key=lambda item: item["days_remaining"]):
            days = row["days_remaining"]
            severity = "CRITICAL" if days < 0 else "HIGH" if days <= 7 else "WARNING"
            style = "bad" if days <= 7 else "warning"
            message = "Certificate expired" if days < 0 else f'Certificate expires in {days} day(s)'
            st.markdown(f'<div class="finding {style}"><b>{severity}:</b> {html.escape(row["domain"])} — {html.escape(message)}. Last scanned {html.escape(row["scanned_at"])}.</div>', unsafe_allow_html=True)
    else:
        st.success("No previously scanned domain is currently recorded as expiring within 30 days.")

# ---------------- SCAN HISTORY AND COMPARISON ----------------
st.markdown('<div class="section-title">🗂 &nbsp; Scan history and comparison</div>', unsafe_allow_html=True)
history = get_history(limit=100)
if history:
    display_rows = [{"Domain": r["domain"], "Scanned at": r["scanned_at"], "Score": r["score"], "Rating": r["score_label"], "Certificate": r["status"], "Days left": r["days_remaining"], "TLS": r["tls_version"]} for r in history]
    st.dataframe(display_rows, use_container_width=True, hide_index=True)
    domains = sorted({r["domain"] for r in history})
    selected_domain = st.selectbox("Choose a domain to compare its scans", domains)
    domain_rows = [r for r in history if r["domain"] == selected_domain]
    if len(domain_rows) >= 2:
        options = {f'#{r["id"]} · {r["scanned_at"]} · score {r["score"]}': r for r in domain_rows}
        labels = list(options.keys())
        old_label = st.selectbox("Earlier scan", labels, index=min(1, len(labels)-1), key="old_scan")
        new_label = st.selectbox("Compare with", labels, index=0, key="new_scan")
        old_row, new_row = options[old_label], options[new_label]
        old_result, new_result = json.loads(old_row["result_json"]), json.loads(new_row["result_json"])
        comparison = []
        for field, label in [("status", "Certificate status"), ("days_remaining", "Days remaining"), ("tls_version", "Negotiated TLS version"), ("cipher", "Cipher suite"), ("issuer", "Certificate issuer"), ("valid_until", "Certificate expiry date")]:
            comparison.append({"Field": label, "Earlier scan": old_result.get(field, "N/A"), "Selected scan": new_result.get(field, "N/A"), "Changed": "Yes" if old_result.get(field) != new_result.get(field) else "No"})
        comparison.append({"Field": "Security score", "Earlier scan": old_row["score"], "Selected scan": new_row["score"], "Changed": "Yes" if old_row["score"] != new_row["score"] else "No"})
        st.dataframe(comparison, use_container_width=True, hide_index=True)
    else:
        st.caption("Scan this domain at least twice to compare how its certificate or TLS details change over time.")
    history_json = json.dumps(display_rows, indent=2)
    st.download_button("⬇ Export scan history (JSON)", data=history_json, file_name="tls_scan_history.json", mime="application/json", use_container_width=True)
else:
    st.info("No scan history yet. Run your first successful scan to start saving results to the local SQLite database.")

# ---------------- FOOTER ----------------
st.markdown('<div class="footer">SENTINEL TLS ANALYZER · EDUCATIONAL CYBERSECURITY PROJECT<br>Verified TLS connections · Local SQLite history · Results reflect scan time</div>', unsafe_allow_html=True)

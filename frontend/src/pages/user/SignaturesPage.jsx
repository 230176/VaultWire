import React, { useMemo, useState } from "react";
import { api } from "../../lib/api";

function downloadText(filename, text) {
  const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

async function readText(file) {
  if (!file) return "";
  return file.text();
}

function FilePicker({ label, help, accept, file, onChange }) {
  return (
    <label style={{ display: "grid", gap: 6 }}>
      <div style={{ fontWeight: 600 }}>{label}</div>
      {help && <small style={{ opacity: 0.85 }}>{help}</small>}
      <input
        type="file"
        accept={accept}
        onChange={(e) => onChange(e.target.files?.[0] || null)}
      />
      <small style={{ opacity: 0.9 }}>
        {file ? `Selected: ${file.name}` : "No file selected yet"}
      </small>
    </label>
  );
}

export default function SignaturesPage() {
  // Sign flow
  const [signFile, setSignFile] = useState(null);
  const [bundle, setBundle] = useState(null);

  // Verify with bundle flow
  const [verifyOriginalFile, setVerifyOriginalFile] = useState(null);
  const [verifyBundleFile, setVerifyBundleFile] = useState(null);

  // Manual verify flow
  const [manualOriginalFile, setManualOriginalFile] = useState(null);
  const [manualCertFile, setManualCertFile] = useState(null);
  const [manualSigFile, setManualSigFile] = useState(null);
  const [manualHash, setManualHash] = useState("");

  const [result, setResult] = useState(null);
  const [msg, setMsg] = useState("");
  const [err, setErr] = useState("");

  const canSign = !!signFile;
  const canVerifyBundle = !!verifyOriginalFile && !!verifyBundleFile;
  const canVerifyManual =
    !!manualOriginalFile &&
    !!manualCertFile &&
    !!manualSigFile &&
    !!manualHash.trim();

  const hasBundle = useMemo(() => !!bundle, [bundle]);

  async function onSign(e) {
    e.preventDefault();
    setErr("");
    setMsg("");
    setResult(null);

    if (!signFile) {
      setErr("Please choose a file to sign.");
      return;
    }

    try {
      const fd = new FormData();
      fd.append("file", signFile);
      const { data } = await api.post("/signatures/sign", fd);

      setBundle(data);
      setMsg("File signed successfully. Download the artifacts below.");
    } catch (e2) {
      setErr(e2.response?.data?.message || "Sign failed");
    }
  }

  async function onVerifyBundle(e) {
    e.preventDefault();
    setErr("");
    setMsg("");
    setResult(null);

    if (!verifyOriginalFile || !verifyBundleFile) {
      setErr("Please upload both original file and bundle JSON.");
      return;
    }

    try {
      const bundleJson = await readText(verifyBundleFile);
      const fd = new FormData();
      fd.append("file", verifyOriginalFile);
      fd.append("bundleJson", bundleJson);

      const { data } = await api.post("/signatures/verify-bundle", fd);
      setResult(data);
      setMsg(
        data?.ok
          ? "Bundle verification succeeded."
          : `Verification failed: ${data?.reason || "UNKNOWN"}`,
      );
    } catch (e2) {
      setErr(e2.response?.data?.message || "Verify with bundle failed");
    }
  }

  async function onVerifyManual(e) {
    e.preventDefault();
    setErr("");
    setMsg("");
    setResult(null);

    if (
      !manualOriginalFile ||
      !manualCertFile ||
      !manualSigFile ||
      !manualHash.trim()
    ) {
      setErr(
        "Manual verify needs: original file + signer-cert.pem + signature.sig + hash.",
      );
      return;
    }

    try {
      const certPem = await readText(manualCertFile);
      const signature = (await readText(manualSigFile)).trim();

      const fd = new FormData();
      fd.append("file", manualOriginalFile);
      fd.append("hash", manualHash.trim());
      fd.append("signature", signature);
      fd.append("certPem", certPem);

      const { data } = await api.post("/signatures/verify", fd);
      setResult(data);
      setMsg(
        data?.ok
          ? "Manual verification succeeded."
          : `Manual verification failed: ${data?.reason || "UNKNOWN"}`,
      );
    } catch (e2) {
      setErr(e2.response?.data?.message || "Manual verify failed");
    }
  }

  return (
    <div>
      <h1>Digital Signatures</h1>

      {msg && <p className="ok">{msg}</p>}
      {err && <p className="bad">{err}</p>}

      {/* Guide */}
      <div className="card" style={{ marginBottom: 16 }}>
        <h3 style={{ marginBottom: 8 }}>How to use</h3>
        <ol style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
          <li>
            Choose a file in <b>Sign file</b> and click <b>Sign</b>.
          </li>
          <li>
            Download <b>signature-bundle.json</b> (and optionally .sig / .pem /
            hash files).
          </li>
          <li>
            To verify, upload the <b>same original file</b> +{" "}
            <b>signature-bundle.json</b>.
          </li>
          <li>
            Expected pass: <code>{'{ "ok": true }'}</code>.
          </li>
          <li>
            Change the file and verify again to test tamper detection (should
            fail).
          </li>
        </ol>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(460px, 1fr))",
          gap: 16,
          alignItems: "start",
        }}
      >
        {/* LEFT: SIGN */}
        <form
          onSubmit={onSign}
          className="card"
          style={{ display: "grid", gap: 12 }}
        >
          <h3 style={{ marginBottom: 2 }}>1) Sign file</h3>

          <FilePicker
            label="File to sign"
            help="Upload any file (pdf, docx, txt, image, etc.)."
            file={signFile}
            onChange={setSignFile}
          />

          <button type="submit" disabled={!canSign}>
            Sign
          </button>

          {hasBundle && (
            <>
              <div style={{ fontWeight: 600, marginTop: 4 }}>
                Download generated artifacts
              </div>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                <button
                  type="button"
                  onClick={() =>
                    downloadText(
                      "signature-bundle.json",
                      JSON.stringify(bundle, null, 2),
                    )
                  }
                >
                  Download bundle.json
                </button>
                <button
                  type="button"
                  onClick={() =>
                    downloadText("signature.sig", bundle?.signature || "")
                  }
                >
                  Download signature.sig
                </button>
                <button
                  type="button"
                  onClick={() => downloadText("hash.txt", bundle?.hash || "")}
                >
                  Download hash.txt
                </button>
                <button
                  type="button"
                  onClick={() =>
                    downloadText("signer-cert.pem", bundle?.signerCertPem || "")
                  }
                >
                  Download signer-cert.pem
                </button>
                {!!bundle?.caCertPem && (
                  <button
                    type="button"
                    onClick={() =>
                      downloadText("ca-cert.pem", bundle?.caCertPem || "")
                    }
                  >
                    Download ca-cert.pem
                  </button>
                )}
              </div>

              <details>
                <summary>View bundle JSON</summary>
                <textarea
                  readOnly
                  rows={12}
                  value={JSON.stringify(bundle, null, 2)}
                />
              </details>
            </>
          )}
        </form>

        {/* RIGHT: VERIFY */}
        <div className="card" style={{ display: "grid", gap: 14 }}>
          <h3 style={{ marginBottom: 0 }}>2) Verify with bundle</h3>
          <form onSubmit={onVerifyBundle} style={{ display: "grid", gap: 10 }}>
            <FilePicker
              label="Original file (same file used during signing)"
              help="Use the exact original file. Any change will fail verification."
              file={verifyOriginalFile}
              onChange={setVerifyOriginalFile}
            />
            <FilePicker
              label="Signature bundle JSON"
              help="Upload signature-bundle.json downloaded from the sign step."
              accept=".json,application/json"
              file={verifyBundleFile}
              onChange={setVerifyBundleFile}
            />
            <button type="submit" disabled={!canVerifyBundle}>
              Verify with bundle
            </button>
          </form>

          <hr
            style={{ borderColor: "rgba(255,255,255,0.15)", width: "100%" }}
          />

          <h3 style={{ marginBottom: 0 }}>3) Manual verify (advanced)</h3>
          <form onSubmit={onVerifyManual} style={{ display: "grid", gap: 10 }}>
            <FilePicker
              label="Original file"
              help="Same file that was signed."
              file={manualOriginalFile}
              onChange={setManualOriginalFile}
            />
            <FilePicker
              label="Signer certificate (.pem)"
              help="Upload signer-cert.pem"
              accept=".pem,text/plain"
              file={manualCertFile}
              onChange={setManualCertFile}
            />
            <FilePicker
              label="Signature file (.sig)"
              help="Upload signature.sig"
              accept=".sig,text/plain"
              file={manualSigFile}
              onChange={setManualSigFile}
            />
            <label style={{ display: "grid", gap: 6 }}>
              <div style={{ fontWeight: 600 }}>SHA-256 hash</div>
              <small style={{ opacity: 0.85 }}>
                Paste value from hash.txt (generated during sign step)
              </small>
              <input
                placeholder="Paste SHA-256 hash"
                value={manualHash}
                onChange={(e) => setManualHash(e.target.value)}
              />
            </label>

            <button type="submit" disabled={!canVerifyManual}>
              Verify manual values
            </button>
          </form>

          <div>
            <h4 style={{ marginBottom: 8 }}>Verification result</h4>
            <pre
              style={{
                border: "1px solid var(--line)",
                borderRadius: 10,
                padding: 10,
                maxHeight: 220,
                overflow: "auto",
                margin: 0,
              }}
            >
              {JSON.stringify(
                result || { ok: null, reason: "No verification yet" },
                null,
                2,
              )}
            </pre>
          </div>
        </div>
      </div>
    </div>
  );
}

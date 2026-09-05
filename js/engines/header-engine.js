// MailSentry AI — Protocol & Authentication Forensics Engine
// Enhanced with display-name spoofing detection and enriched anomaly reporting

window.HeaderEngine = {
  analyzeHeaders(parsedEmail) {
    const authResults = (parsedEmail.authResults || '').toLowerCase();
    const fromDomain       = (parsedEmail.from.domain   || '').toLowerCase();
    const returnPathDomain = (parsedEmail.returnPath?.domain || '').toLowerCase();
    const replyToDomain    = (parsedEmail.replyTo?.domain   || '').toLowerCase();
    const fromName         = (parsedEmail.from.name     || '').toLowerCase();

    // SPF
    let spfStatus = 'NEUTRAL';
    if (authResults.includes('spf=pass'))     spfStatus = 'PASS';
    else if (authResults.includes('spf=fail')) spfStatus = 'FAIL';
    else if (authResults.includes('spf=softfail')) spfStatus = 'SOFTFAIL';
    else if (authResults.includes('spf=none')) spfStatus = 'NONE';

    // DKIM
    let dkimStatus = 'NEUTRAL';
    if (authResults.includes('dkim=pass')) dkimStatus = 'PASS';
    else if (authResults.includes('dkim=fail') || authResults.includes('bad signature') || authResults.includes('no key')) dkimStatus = 'FAIL';
    else if (authResults.includes('dkim=none')) dkimStatus = 'NONE';

    // DMARC
    let dmarcStatus = 'NONE';
    if (authResults.includes('dmarc=pass')) dmarcStatus = 'PASS';
    else if (authResults.includes('dmarc=fail')) dmarcStatus = 'FAIL';

    // Alignment checks
    const isReturnPathAligned = !returnPathDomain || fromDomain === returnPathDomain;
    const isReplyToAligned    = !replyToDomain    || fromDomain === replyToDomain;

    // Display-name spoofing: "State Bank of India" from non-sbi domain
    const bankKeywords = ['bank', 'sbi', 'hdfc', 'icici', 'rbi', 'npci', 'gst', 'income tax', 'uidai', 'irctc', 'sebi', 'cert', 'paytm', 'phonepe'];
    const isDisplaySpoofed = bankKeywords.some(kw => fromName.includes(kw)) && !bankKeywords.some(kw => fromDomain.includes(kw));

    // x-mailer anomalies
    const xMailer = (parsedEmail.xMailer || '').toLowerCase();
    const isSuspiciousMailer = ['yandex', 'proton', 'mail.ru', 'tutanota', 'guerrilla'].some(m => xMailer.includes(m));

    const anomalies = [];
    if (!isReturnPathAligned && returnPathDomain)
      anomalies.push(`Return-Path Mismatch (${returnPathDomain} ≠ ${fromDomain})`);
    if (!isReplyToAligned && replyToDomain)
      anomalies.push(`Reply-To Hijack → Replies routed to ${replyToDomain}`);
    if (spfStatus === 'FAIL')
      anomalies.push('SPF Failed — Origin IP not permitted in sender DNS');
    if (dkimStatus === 'FAIL')
      anomalies.push('DKIM Signature Forged — Cryptographic integrity broken');
    if (dmarcStatus === 'FAIL')
      anomalies.push('DMARC Policy Violated — Domain enforcement triggered');
    if (isDisplaySpoofed)
      anomalies.push('Display Name Spoofing — Financial institution impersonated');
    if (isSuspiciousMailer)
      anomalies.push(`Suspicious X-Mailer: ${parsedEmail.xMailer}`);

    const authScore = (spfStatus === 'PASS' ? 0 : spfStatus === 'SOFTFAIL' ? 10 : 20) +
                      (dkimStatus === 'PASS' ? 0 : 18) +
                      (dmarcStatus === 'PASS' ? 0 : 15);

    return {
      spfStatus, dkimStatus, dmarcStatus,
      isReturnPathAligned, isReplyToAligned,
      isDisplaySpoofed, isSuspiciousMailer,
      anomalies, authScore
    };
  }
};

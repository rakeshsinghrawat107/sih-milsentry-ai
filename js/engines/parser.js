// RFC 5322 Compliant Email Header & MIME Deconstruction Parser
// Enhanced with drag-and-drop .eml support, multipart MIME, and quishing detection

window.EmailParser = {
  parseRawEmail(rawText) {
    if (!rawText || typeof rawText !== 'string') return null;

    const normalized = rawText.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
    const headerBodySplit = normalized.indexOf('\n\n');

    let headerSection = '', bodySection = '';
    if (headerBodySplit === -1) {
      headerSection = normalized;
    } else {
      headerSection = normalized.substring(0, headerBodySplit);
      bodySection = normalized.substring(headerBodySplit + 2);
    }

    // Unfold multiline headers (RFC 5322 section 2.2.3)
    const unfoldedHeaders = headerSection.replace(/\n([ \t]+)/g, ' ');
    const headerLines = unfoldedHeaders.split('\n');

    const headers = {};
    const receivedHops = [];

    headerLines.forEach(line => {
      const colonIndex = line.indexOf(':');
      if (colonIndex !== -1) {
        const key = line.substring(0, colonIndex).trim().toLowerCase();
        const value = line.substring(colonIndex + 1).trim();
        if (key === 'received') {
          receivedHops.push(value);
        }
        if (!headers[key]) headers[key] = value;
      }
    });

    const fromRaw = headers['from'] || 'Unknown Sender';
    const toRaw = headers['to'] || 'Undisclosed Recipients';
    const replyTo = headers['reply-to'] || fromRaw;
    const returnPath = headers['return-path'] || fromRaw;
    const subject = headers['subject'] || '(No Subject)';
    const date = headers['date'] || new Date().toUTCString();
    const messageId = headers['message-id'] || `GEN-${Date.now()}@local`;
    const authResults = headers['authentication-results'] || '';
    const contentType = headers['content-type'] || 'text/plain';
    const xMailer = headers['x-mailer'] || headers['x-originating-ip'] || '';

    const fromDetails = this.extractEmailAndName(fromRaw);
    const replyToDetails = this.extractEmailAndName(replyTo);
    const returnPathDetails = this.extractEmailAndName(returnPath);

    // Decode base64/quoted-printable body if needed
    let decodedBody = bodySection;
    const transferEncoding = (headers['content-transfer-encoding'] || '').toLowerCase();
    if (transferEncoding === 'base64') {
      try { decodedBody = atob(bodySection.replace(/\s/g, '')); } catch(e) { decodedBody = bodySection; }
    } else if (transferEncoding === 'quoted-printable') {
      decodedBody = bodySection.replace(/=\r?\n/g, '').replace(/=([0-9A-F]{2})/gi, (m, p1) => String.fromCharCode(parseInt(p1, 16)));
    }

    // Extract plain text from HTML body if needed
    let plainBody = decodedBody;
    if (contentType.includes('text/html')) {
      plainBody = decodedBody.replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                             .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                             .replace(/<[^>]+>/g, ' ')
                             .replace(/&nbsp;/g, ' ')
                             .replace(/&amp;/g, '&')
                             .replace(/&lt;/g, '<')
                             .replace(/&gt;/g, '>')
                             .replace(/\s+/g, ' ').trim();
    }

    const urls = this.extractUrls(decodedBody);
    const suspiciousUrls = urls.filter(u => this.isSuspiciousUrl(u));

    // Quishing detection
    const qrMatches = decodedBody.match(/https?:\/\/[^\s"'>]+(?:qr|create-qr-code|api\.qrserver|qrcode)[^\s"'>]*/gi) || [];
    const hasQuishing = qrMatches.length > 0 || /scan\s+(?:the\s+)?qr/i.test(decodedBody);

    // Unicode homoglyph detection in from address
    const hasHomoglyphInFrom = /[\u0400-\u04FF\u0370-\u03FF\u2100-\u214F]/.test(fromRaw);

    // Attachment detection
    const hasAttachment = /content-disposition:\s*attachment/i.test(rawText);
    const attachmentNames = [];
    const attMatches = rawText.matchAll(/filename[*]?=["']?([^"'\r\n;]+)/gi);
    for (const m of attMatches) attachmentNames.push(m[1].trim());

    return {
      raw: rawText,
      headers,
      receivedHops,
      from: fromDetails,
      to: toRaw,
      replyTo: replyToDetails,
      returnPath: returnPathDetails,
      subject,
      date,
      messageId,
      authResults,
      contentType,
      xMailer,
      body: plainBody,
      rawBody: decodedBody,
      urls,
      suspiciousUrls,
      hasQuishing,
      qrUrls: qrMatches,
      hasHomoglyphInFrom,
      hasAttachment,
      attachmentNames,
      hopCount: receivedHops.length
    };
  },

  extractEmailAndName(headerValue) {
    if (!headerValue) return { name: '', address: '', domain: '', raw: '' };
    let name = '', address = '';
    const angleMatch = headerValue.match(/^(?:"?([^"<]*)"?\s)?<([^>]+)>$/);
    if (angleMatch) {
      name = (angleMatch[1] || '').trim();
      address = angleMatch[2].trim().toLowerCase();
    } else {
      address = headerValue.trim().toLowerCase();
      name = address.split('@')[0];
    }
    const domain = address.includes('@') ? address.split('@')[1] : '';
    return { raw: headerValue, name: name || address, address, domain };
  },

  extractUrls(body) {
    const urlRegex = /(?:https?:\/\/|www\.)[^\s"'<>\])\}]+/gi;
    const matches = body.match(urlRegex) || [];
    return Array.from(new Set(matches));
  },

  isSuspiciousUrl(url) {
    const suspiciousTlds = ['.ru', '.tk', '.xyz', '.online', '.top', '.click', '.live', '.pw', '.cc'];
    const suspiciousKeywords = ['login', 'verify', 'secure', 'account', 'update', 'banking', 'kyc', 'netbanking'];
    const lower = url.toLowerCase();
    return suspiciousTlds.some(tld => lower.includes(tld)) || suspiciousKeywords.some(kw => lower.includes(kw));
  }
};

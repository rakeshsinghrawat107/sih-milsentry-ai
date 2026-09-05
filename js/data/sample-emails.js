// Pre-loaded realistic RFC 5322 test emails for instant demonstration
// 5 scenarios: SBI Phishing, CEO BEC, GST Quishing, IT Refund Spoof, Clean Baseline

window.SAMPLE_EMAILS = {
  sbi_phish: {
    id: 'sample-sbi-phish',
    title: '🚨 SBI KYC Phishing (Cyrillic Homoglyph)',
    category: 'PHISHING',
    raw: `Delivered-To: victim.user@corporate-bank.in
Received: by 2002:a05:6512:444 with SMTP id d4csp1023243lfb;
        Mon, 1 Sep 2026 14:22:15 +0530 (IST)
Received: from mail.sbi-kyc-update.ru (mail.sbi-kyc-update.ru. [185.220.101.5])
        by mx.google.com with ESMTP id q12si8892112plm.12.2026.09.01.01.52.14
        for <victim.user@corporate-bank.in>;
        Mon, 01 Sep 2026 01:52:14 -0700 (PDT)
Received: from localhost (unknown [194.26.29.112])
        by mail.sbi-kyc-update.ru (Postfix) with ESMTP id 4X9L1K0Z12z401;
        Mon, 1 Sep 2026 11:51:40 +0300 (MSK)
Authentication-Results: mx.google.com;
       dkim=neutral (bad signature) header.i=@sbi-kyc-update.ru;
       spf=fail (google.com: domain of support@sbi.co.in does not designate 185.220.101.5 as permitted sender) smtp.mailfrom=support@sbi.co.in;
       dmarc=fail (p=REJECT sp=REJECT dis=NONE) header.from=sbi.co.in
Return-Path: <support@sbi-alert.ru>
From: "State Bank of India Online" <alerts@sbі-support.co.in>
To: "Valued Customer" <victim.user@corporate-bank.in>
Reply-To: "Customer Desk" <sbi.recovery2026@yandex.com>
Subject: URGENT: Complete Your Mandatory Aadhaar-PAN KYC Within 24 Hours to Prevent Account Suspension
Date: Mon, 1 Sep 2026 14:20:00 +0530
Message-ID: <20260901142000.84920.sbi-scam@yandex.ru>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; color: #333;">
  <div style="border: 2px solid #003366; padding: 20px; max-width: 600px;">
    <h2 style="color: #003366;">STATE BANK OF INDIA - MANDATORY COMPLIANCE NOTICE</h2>
    <p>Dear Customer,</p>
    <p>Your SBI NetBanking profile has been temporarily flagged due to unverified Aadhaar-PAN linkage under RBI Master Circular 2026/KYC-09.</p>
    <p style="color: red; font-weight: bold;">Failure to update your KYC within 24 hours will result in immediate permanent blocking of debit cards, UPI payments, and IMPS outbound transfers.</p>
    <p>Please click the secure verification portal below immediately to complete verification:</p>
    <p style="text-align: center; margin: 30px 0;">
      <a href="http://sbi-secure-portal.net.ru/login.php?session=928492" style="background-color: #003366; color: #ffffff; padding: 12px 25px; text-decoration: none; font-weight: bold; border-radius: 4px;">VERIFY SBI ACCOUNT NOW</a>
    </p>
    <p>Warm regards,<br>Chief Risk Officer, State Bank of India<br>State Bank Bhavan, Nariman Point, Mumbai</p>
  </div>
</body>
</html>`
  },

  bec_ceo: {
    id: 'sample-bec-ceo',
    title: '💼 CEO Wire Fraud (Business Email Compromise)',
    category: 'BEC',
    raw: `Delivered-To: cfo.sharma@national-aerospace.gov.in
Received: by 2002:a17:907:741:b0:9a1:d356:f12 with SMTP id e1csp9421111prb;
        Mon, 1 Sep 2026 15:40:02 +0530 (IST)
Received: from out-relay.vpn-fastnode.ch (out-relay.vpn-fastnode.ch [185.156.73.44])
        by mx.nic.in with ESMTP id k91si9011421nic.22.2026.09.01.03.10.01;
        Mon, 01 Sep 2026 15:40:01 +0530 (IST)
Authentication-Results: mx.nic.in;
       spf=fail (nic.in: domain of rajesh.verma@national-aerospace.gov.in does not designate 185.156.73.44 as permitted sender);
       dkim=fail (no key);
       dmarc=fail (p=QUARANTINE) header.from=national-aerospace.gov.in
Return-Path: <spoofed-relay@vpn-fastnode.ch>
From: "Dr. Rajesh Verma (Director General)" <director@natioanal-aerospace.gov.in>
To: "Anoop Sharma (Finance Head)" <cfo.sharma@national-aerospace.gov.in>
Reply-To: "Rajesh Verma Private" <dg.verma.confidential@proton.me>
X-Mailer: ProtonMail Bridge 3.1.0
Subject: CONFIDENTIAL & URGENT: Acquisition Settlement Payment - Authorization Required Immediately
Date: Mon, 1 Sep 2026 15:38:12 +0530
Message-ID: <NACL-DIRECTOR-URGENT-981249@proton.me>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Anoop,

I am currently in an urgent closed-door review committee meeting with the Ministry and cannot take phone calls.

We have finalized the confidential settlement tranche for the upcoming strategic vendor contract. The escrow payment of ₹85,00,000 (Eighty-Five Lakhs INR) must be cleared before 5:00 PM today via RTGS to avoid statutory penalties.

Please wire the funds directly to our designated settlement escrow account:
Beneficiary: Apex Defense Strategic Consultancy LLP
Account: 92810029381944
IFSC: HDFC0001092
Branch: Connaught Place, New Delhi

Reply directly to this email once the UTR number is generated. Do not discuss this with the floor team until the Ministry press release tomorrow. Strictly confidential.

Dr. Rajesh Verma
Director General
National Aerospace Corporation Ltd.`
  },

  quishing_qr: {
    id: 'sample-quishing-qr',
    title: '📷 GST Invoice QR Quishing Attack',
    category: 'QUISHING',
    raw: `Delivered-To: accounts@infra-powercorp.in
Received: by 2002:a05:6214:241 with SMTP id a1csp241198plb;
        Mon, 1 Sep 2026 11:10:04 +0530 (IST)
Received: from bulkmail-host.nl (bulkmail-host.nl [45.142.122.18])
        by mx.google.com with ESMTP id r1si2981234qkp.55.2026.09.01.11.10.03;
        Mon, 01 Sep 2026 11:10:03 +0530 (IST)
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of billing@gst.gov.in does not designate 45.142.122.18 as permitted sender);
       dkim=fail;
       dmarc=fail (p=REJECT) header.from=gst.gov.in
Return-Path: <noreply@gst-verify-portal.xyz>
From: "GST Compliance Team" <billing@gst-verify-portal.xyz>
To: "Accounts Payable" <accounts@infra-powercorp.in>
Reply-To: "GST Helpdesk" <refunds@gst-helpdesk.online>
Subject: ACTION REQUIRED: Verify GST Invoice via QR Code — ITC Mismatch Detected (GSTIN: 09AABCU9603R1ZX)
Date: Mon, 1 Sep 2026 11:08:00 +0530
Message-ID: <GST-PORTAL-NOTICE-20260901@gst-verify-portal.xyz>
MIME-Version: 1.0
Content-Type: text/html; charset="UTF-8"

<!DOCTYPE html>
<html>
<body>
  <div style="border: 2px solid #006400; padding: 20px; max-width: 600px; font-family: Arial, sans-serif;">
    <img src="https://upload.wikimedia.org/wikipedia/commons/thumb/5/55/Emblem_of_India.svg/240px-Emblem_of_India.svg.png" width="60" alt="Emblem of India">
    <h2 style="color:#006400;">GOODS AND SERVICES TAX NETWORK (GSTN)</h2>
    <p>Dear Taxpayer,</p>
    <p>An ITC mismatch has been detected in your GSTR-3B filing for the period <strong>August 2026</strong>. Immediate verification is mandatory to avoid a penalty notice under Section 73 of the CGST Act.</p>
    <p style="color:red; font-weight:bold;">Scan the QR code below using your GSTZen app to confirm and validate your invoice data:</p>
    <div style="text-align:center; margin: 20px 0;">
      <img src="https://api.qrserver.com/v1/create-qr-code/?size=180x180&data=http://gst-itc-verify.xyz/login?gstin=09AABCU9603R1ZX&token=STEAL_CRED" alt="GST Verification QR Code" style="border: 4px solid #006400;">
    </div>
    <p>If QR code does not work, click here: <a href="http://gst-itc-verify.xyz/login">Verify Now</a></p>
    <p>Regards,<br>GST Grievance Cell<br>Ministry of Finance, Government of India</p>
  </div>
</body>
</html>`
  },

  it_refund_spoof: {
    id: 'sample-it-refund',
    title: '💰 Income Tax Refund Advance Fee Scam',
    category: 'ADVANCE_FEE_FRAUD',
    raw: `Delivered-To: taxpayer.gupta@mycompany.co.in
Received: by 2002:a05:6512:3894 with SMTP id z1csp3219prb;
        Fri, 4 Sep 2026 09:30:00 +0530 (IST)
Received: from smtp-relay.selectel.ru (smtp-relay.selectel.ru [46.161.27.151])
        by mx.google.com with ESMTP id n91si2011432goo.44.2026.09.04.04.00.00;
        Fri, 04 Sep 2026 09:29:59 +0530 (IST)
Authentication-Results: mx.google.com;
       spf=fail (google.com: domain of refund@incometax.gov.in does not designate 46.161.27.151 as permitted sender);
       dkim=fail;
       dmarc=fail (p=REJECT) header.from=incometax.gov.in
Return-Path: <refunds@income-tax-refund.xyz>
From: "Income Tax Department India" <refund@incometax-refund.online>
To: "Mr. Ramesh Gupta" <taxpayer.gupta@mycompany.co.in>
Reply-To: "IT Refund Processing" <it.refund.processing2026@yandex.com>
Subject: IMPORTANT: Your Income Tax Refund of ₹38,492 is Ready — Verify Bank Details Immediately
Date: Fri, 4 Sep 2026 09:28:00 +0530
Message-ID: <ITD-REFUND-2026-38492@income-tax-refund.xyz>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear Taxpayer,

The Income Tax Department of India has processed your ITR-1 return for AY 2026-27.

Your tax refund of Rs. 38,492 (Thirty-Eight Thousand Four Hundred Ninety Two Rupees) is ready for disbursement via NEFT to your registered bank account.

ACTION REQUIRED: To release your refund, you must verify your bank account details immediately by logging into the secure portal. Failure to verify within 24 hours will result in automatic lapse of refund under Section 244A of the Income Tax Act.

Claim your ITR Refund: http://it-refund-portal.xyz/verify?pan=ABCPG1234F&token=928abc

You may also be required to pay a small processing fee of Rs. 199 to activate the refund transfer to your linked Aadhaar. This is a mandatory CBDT directive.

Yours sincerely,
AO - Centralized Processing Centre
Income Tax Department
Ministry of Finance, Government of India
Ref: CPC/2026/38492/AUTO`
  },

  legitimate_mail: {
    id: 'sample-legitimate',
    title: '✅ Clean Corporate Email (Baseline)',
    category: 'LEGITIMATE',
    raw: `Delivered-To: employee@trustedcorp.in
Received: by 2002:a05:6214:28ca with SMTP id t10csp4512567lfo;
        Mon, 1 Sep 2026 10:01:00 +0530 (IST)
Received: from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.216.44])
        by mx.google.com with SMTPS id a98si1234sor.22.2026.09.01.10.00.59
        for <employee@trustedcorp.in>;
        Mon, 01 Sep 2026 10:00:59 +0530 (IST)
Authentication-Results: mx.google.com;
       dkim=pass header.i=@trustedcorp.in header.s=google header.b=abcXYZ12;
       spf=pass (google.com: domain of hr@trustedcorp.in designates 209.85.216.44 as permitted sender) smtp.mailfrom=hr@trustedcorp.in;
       dmarc=pass (p=QUARANTINE sp=NONE dis=NONE) header.from=trustedcorp.in
Return-Path: <hr@trustedcorp.in>
From: "Priya Mehta — HR Head" <hr@trustedcorp.in>
To: "All Employees" <employee@trustedcorp.in>
Reply-To: <hr@trustedcorp.in>
Subject: September 2026 Payroll Processing Complete — Salary Credit Notification
Date: Mon, 1 Sep 2026 09:58:00 +0530
Message-ID: <20260901095800.12345.trustedcorp@google.com>
MIME-Version: 1.0
Content-Type: text/plain; charset="UTF-8"

Dear Team,

This is to confirm that September 2026 salary processing has been completed successfully. Salaries have been credited to all registered bank accounts as of today, 1st September 2026.

Please check your bank statement or net banking portal for the credit. In case of any discrepancy, contact the payroll team at payroll@trustedcorp.in by 5th September 2026.

Regards,
Priya Mehta
Head — Human Resources
TrustedCorp India Pvt. Ltd.
Registered Office: 14th Floor, DLF Cyber City, Gurugram — 122002`
  }
};

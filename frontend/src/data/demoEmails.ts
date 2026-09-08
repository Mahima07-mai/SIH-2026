import type { AnalyzeRequestBody } from "../services/api";

export interface DemoEmail {
  key: string;
  label: string;
  description: string;
  payload: AnalyzeRequestBody;
}

export const DEMO_EMAILS: DemoEmail[] = [
  {
    key: "benign",
    label: "Benign",
    description: "A routine, internally-consistent newsletter email.",
    payload: {
      label: "Demo: Benign",
      headers: {
        from_address: "newsletter@github.com",
        reply_to: "newsletter@github.com",
        return_path: "bounce@github.com",
        subject: "Your weekly digest is ready",
        message_id: "<abc123@github.com>",
        date: "Mon, 01 Sep 2026 09:00:00 +0000",
        authentication_results:
          "mx.google.com; spf=pass smtp.mailfrom=github.com; dkim=pass header.d=github.com; dmarc=pass header.from=github.com",
        dkim_signature: "v=1; a=rsa-sha256; d=github.com; s=default; ...",
        received:
          "from mail-sor-f41.google.com (mail-sor-f41.google.com [209.85.220.41]) by mx.example.com; Mon, 01 Sep 2026 09:00:01 +0000",
      },
      body: {
        plain_text:
          "Hi there,\n\nHere's what happened in your repositories this week. Check out trending issues and pull requests.\n\nView your digest: https://github.com/notifications\n\nThanks,\nThe GitHub Team",
      },
      urls: ["https://github.com/notifications"],
      attachments: [],
    },
  },
  {
    key: "phishing",
    label: "Phishing",
    description: "Credential phishing with a Reply-To mismatch and lookalike domain.",
    payload: {
      label: "Demo: Phishing",
      headers: {
        from_address: '"Secure Bank Support" <support@secure-bank.com>',
        reply_to: "support@gmail.com",
        return_path: "bounce@secure-bank.com",
        subject: "URGENT: Your account will be suspended",
        message_id: "<xyz789@secure-bank.com>",
        date: "Mon, 01 Sep 2026 03:12:00 +0000",
        authentication_results:
          "mx.google.com; spf=fail smtp.mailfrom=secure-bank.com; dkim=none; dmarc=fail header.from=secure-bank.com",
        received:
          "from unknown (45.137.22.9) by mx.example.com; Mon, 01 Sep 2026 03:12:01 +0000",
      },
      body: {
        plain_text:
          "Your account has been flagged for suspicious activity. Verify your password immediately using the link below, otherwise your account will be permanently suspended within 24 hours.\n\nVerify now: https://secure-bank-login.example.com/verify\n\nSecure Bank Security Team",
      },
      urls: ["https://secure-bank-login.example.com/verify"],
      attachments: [],
    },
  },
  {
    key: "bec",
    label: "BEC",
    description: "Executive impersonation requesting an urgent wire payment.",
    payload: {
      label: "Demo: BEC",
      headers: {
        from_address: '"John Carter (CEO)" <john.carter@corp-mail.co>',
        reply_to: "j.carter1990@outlook.com",
        return_path: "bounce@corp-mail.co",
        subject: "Quick task - confidential",
        message_id: "<bec001@corp-mail.co>",
        date: "Mon, 01 Sep 2026 08:05:00 +0000",
        authentication_results:
          "mx.google.com; spf=softfail smtp.mailfrom=corp-mail.co; dkim=none; dmarc=fail header.from=corp-mail.co",
        received: "from 103.22.4.18 by mx.example.com; Mon, 01 Sep 2026 08:05:02 +0000",
      },
      body: {
        plain_text:
          "Hi, I'm in a meeting and need you to process an urgent wire transfer to a new vendor today before 2pm. This is time sensitive and confidential — please don't discuss with anyone else. I'll send the bank details shortly.\n\nJohn",
      },
      urls: [],
      attachments: [],
    },
  },
  {
    key: "malware",
    label: "Malware",
    description: "Invoice-themed email with a macro-enabled Office attachment.",
    payload: {
      label: "Demo: Malware",
      headers: {
        from_address: "billing@office-invoices-portal.net",
        reply_to: "billing@office-invoices-portal.net",
        subject: "Invoice #48213 attached",
        message_id: "<inv48213@office-invoices-portal.net>",
        date: "Mon, 01 Sep 2026 11:40:00 +0000",
        authentication_results:
          "mx.google.com; spf=fail smtp.mailfrom=office-invoices-portal.net; dkim=none; dmarc=fail",
        received: "from 185.220.101.4 by mx.example.com; Mon, 01 Sep 2026 11:40:03 +0000",
      },
      body: {
        plain_text:
          "Please find attached the invoice for last month's services. Enable macros/editing to view the formatted invoice correctly.\n\nRegards,\nBilling Department",
      },
      urls: [],
      attachments: [
        {
          filename: "Invoice_48213.docm",
          mime_type: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
          size: 5,
          // Minimal placeholder bytes (not a real macro doc) — good enough
          // to exercise the pipeline's extension/MIME-mismatch + macro path
          // in a demo without shipping an actual weaponized file.
          content_base64: btoa("DEMO"),
        },
      ],
    },
  },
  {
    key: "spoofing",
    label: "Spoofing",
    description: "Authentication failure and header contradictions, low semantic phishing content.",
    payload: {
      label: "Demo: Spoofing",
      headers: {
        from_address: "alerts@yourcompany.com",
        reply_to: "alerts@totally-different-domain.io",
        return_path: "bounce@totally-different-domain.io",
        subject: "System notification",
        message_id: "<sys001@yourcompany.com>",
        date: "Mon, 01 Sep 2026 14:00:00 +0000",
        authentication_results:
          "mx.google.com; spf=fail smtp.mailfrom=yourcompany.com; dkim=fail; dmarc=fail header.from=yourcompany.com",
        received: "from 91.219.212.7 by mx.example.com; Mon, 01 Sep 2026 14:00:04 +0000",
      },
      body: {
        plain_text: "This is an automated system notification. No action is required at this time.",
      },
      urls: [],
      attachments: [],
    },
  },
];

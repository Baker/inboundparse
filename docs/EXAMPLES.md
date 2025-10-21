# Swaks Example Usages

These example commands use [`swaks`](https://www.jetmore.org/john/code/swaks/) (Swiss Army Knife for SMTP) to send test emails to your local InboundParse instance. Feel free to modify the addresses and content!

---

## 1. Send a rich email with plain text and HTML versions

```shell
swaks \
  --to user@example.com \
  --from "📧 Baker <me@example.com>" \
  --server 127.0.0.1:2525 \
  --header "Subject: HTML Email Example / Ejemplo de Correo HTML" \
  --header "Cc: cc-user@example.com" \
  --header "Bcc: bcc-user@example.com" \
  --body "<html><body><h1>Product Updates</h1><p>We've launched <a href='https://yourdomain.com/new-features'>exciting new features</a>!</p></body></html>" \
  --add-header "Content-Type: text/html"
```

---

## 2. Send to multiple recipients (To, CC, BCC)

```shell
swaks \
  --to user@example.com,user2@example.com,user3@example.com \
  --from "📧 Baker <me@example.com>" \
  --server 127.0.0.1:2525 \
  --header "Subject: Multi-recipient Email Test" \
  --header "Cc: cc-user@example.com,cc2@example.com" \
  --header "Bcc: bcc-user@example.com,bcc2@example.com" \
  --attach-type text/plain \
  --attach-body "Testing multi-recipient delivery and visibility with Swaks on InboundParse." \
  --attach-type text/html \
  --attach-body '<html><body>
    <h2>Multi-Recipient Email</h2>
    <ul>
      <li><b>To:</b> user@example.com, user2@example.com, user3@example.com</li>
      <li><b>Cc:</b> cc-user@example.com, cc2@example.com</li>
      <li><b>Bcc:</b> bcc-user@example.com, bcc2@example.com</li>
    </ul>
    <p>This message tests <i>To</i>, <i>Cc</i>, and <i>Bcc</i> handling.</p>
    </body></html>'
```

---

**Tip:**  
- Try changing `--server 127.0.0.1:2525` to your actual SMTP/InboundParse address and port, e.g., `0.0.0.0:25` or a TLS port if configured.
- Swaks will show the SMTP dialog and response after sending. You can also use `--body` for simpler single-part messages.
- For authentication tests, add `--auth` and related options as needed.

For more details: [Swaks documentation](https://www.jetmore.org/john/code/swaks/)
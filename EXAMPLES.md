# Swasks Examples


```shell
swaks --to user@example.com \
      --from me@example.com \
      --server 127.0.0.1:2525 \
      --header "From: 📧 Baker <me@example.com>" \
      --header "Subject: HTML Email Example / Ejemplo de Correo HTML" \
      --header "Cc: cc-user@example.com" \
      --header "Bcc: bcc-user@example.com" \
      --attach-type text/plain \
      --attach-body "Hello! This is the plain text version of the email. You can visit Wikipedia at: https://en.wikipedia.org/wiki/Main_Page" \
      --attach-type text/html \
      --attach-body '<html><body><h1>Hello!</h1><p>This is an <b>HTML</b> email.</p><a href="https://en.wikipedia.org/wiki/Main_Page">Wikipedia</a></body></html>'
```

```shell
swaks --to user@example.com,user2@example.com,user3@example.com \
      --from me@example.com \
      --server 127.0.0.1:2525 \
      --header "From: 📧 Baker <me@example.com>" \
      --header "Subject: HTML Email Example / Ejemplo de Correo HTML" \
      --header "Cc: cc-user@example.com" \
      --header "Bcc: bcc-user@example.com" \
      --attach-type text/plain \
      --attach-body "Hello! This is the plain text version of the email. You can visit Wikipedia at: https://en.wikipedia.org/wiki/Main_Page" \
      --attach-type text/html \
      --attach-body '<html><body><h1>Hello!</h1><p>This is an <b>HTML</b> email.</p><a href="https://en.wikipedia.org/wiki/Main_Page">Wikipedia</a></body></html>'
```
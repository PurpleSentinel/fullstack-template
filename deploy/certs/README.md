Place TLS files here for local runs:

- `tls.crt`
- `tls.key`

Generate self-signed certs:

```sh
openssl req -x509 -newkey rsa:4096 -sha256 -days 365 -nodes \
  -keyout deploy/certs/tls.key \
  -out deploy/certs/tls.crt \
  -subj "/CN=localhost"
```

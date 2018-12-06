# Task 3 instructions for creating keys

## Create a CA-cert + public CA-key

```bash
openssl req -x509 -newkey rsa:2048 -keyout ca.key.pem -out ca.cert.pem -nodes -days 365
```

## Create a CSR

```bash
openssl req -out user.csr.csr -new -newkey rsa:2048 -nodes -keyout user.private.key
```

## Sign CSR

```bash
openssl x509 -req -days 360 -in user.csr.csr -CA ca.cert.pem -CAkey ca.key.pem -CAcreateserial -out user.sha1.pem -sha256
```

## Translate PEM key to DER

```bash
openssl pkcs8 -nocrypt -topk8 -inform PEM -in ca.key.pem  -outform DER -out
```

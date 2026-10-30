# Zunder Licensing

Painel web para gerar e gerenciar as licencas do **Zunder Optimizer**.

- Login com senha de admin
- Gera chave assinada (ECDSA P-256) com nome, HWID e validade
- Lista todas as licencas emitidas
- Revoga / restaura licencas
- Endpoint publico `/api/verify` para checagem online

## Rodar local

```powershell
npm install
copy .env.example .env   # preencha os valores
$env:ADMIN_PASSWORD="sua-senha"; $env:LICENSE_PRIVATE_KEY="..."; $env:SESSION_SECRET="..."; npm start
```

Abre em http://localhost:3000

## Deploy no Railway

1. Instale a CLI: `npm i -g @railway/cli`
2. Login: `railway login` (ou use `RAILWAY_API_TOKEN`)
3. `cd ZunderLicensing`
4. `railway init -n zunder-licensing`
5. Variaveis:
   ```
   railway variables --set ADMIN_PASSWORD=sua-senha-forte
   railway variables --set SESSION_SECRET=<string-aleatoria>
   railway variables --set LICENSE_PRIVATE_KEY=<base64-pkcs8>
   railway variables --set DATA_DIR=/data
   ```
6. Volume persistente (para nao perder o historico): no dashboard do Railway,
   adicione um Volume montado em `/data`.
7. `railway up`
8. `railway domain` para gerar o dominio publico.

## Endpoint de verificacao

```
GET /api/verify?key=ZNDR1....
-> {"ok":true,"name":"Fulano","expiry":1795978659}
-> {"ok":false,"reason":"revogada" | "expirada" | "nao encontrada"}
```

## Seguranca

- A `LICENSE_PRIVATE_KEY` assina as licencas: mantenha so neste servidor e no keygen local.
- Use `ADMIN_PASSWORD` forte e `SESSION_SECRET` aleatorio.
- O painel nao expoe a chave privada em nenhum endpoint.

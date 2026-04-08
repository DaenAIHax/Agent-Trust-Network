# Cullis E2E Test — Full-Stack Integration

Automatizza il flusso end-to-end che facevamo a mano: deploy del broker, due
MCP proxy, registrazione di due org, creazione di due agent, scambio di un
messaggio E2E criptato fra le due org, decifratura verificata.

In una sola parola: **se questo test passa, sappiamo che la demo manuale
del 7-8 aprile continua a funzionare.**

---

## Quando lo usi

- **Prima di un PR su `main`** che tocca broker, mcp_proxy, auth, broker
  bridge, AgentManager, o anything graceful-shutdown / persistence
- **Dopo un upgrade di dipendenze** (cryptography, fastapi, sqlalchemy)
- **Prima di un deploy in produzione** se il rilascio include cambiamenti
  al protocollo (DPoP, AAD, signing)
- **Quando ricordi che esiste e ti senti in colpa di non averlo lanciato**

Non è in CI di default — gira ~3 minuti, non ha senso bloccare ogni push.
L'idea è che tu (o un cron notturno) lo lanci esplicitamente.

---

## Come si lancia

### Modo veloce — wrapper

```bash
tests/e2e/run.sh
```

Lo script:
1. Verifica che `docker` e `pytest` siano disponibili
2. Pulisce qualsiasi stack `cullis-e2e` lasciato in giro
3. Builda i container (broker + 2 proxy)
4. Avvia tutto, aspetta che `/healthz` di ogni servizio sia 200
5. Esegue i test pytest con `-m e2e -s -v`
6. Smonta tutto (anche se i test falliscono)

### Tempi attesi

| Fase | Prima volta | Run successivi |
|---|---|---|
| 1. Cleanup stack vecchi | ~5s | ~5s |
| 2. **Build immagini Docker** | **60-180s** (pip install in container) | ~5s (cache) |
| 3. Boot containers (postgres → vault → redis → broker → 2 proxy) | ~30-60s | ~30-60s |
| 4. Health polling | ~10-30s | ~10-30s |
| 5. Esecuzione 3 test | ~30-60s | ~30-60s |
| 6. Teardown | ~5-10s | ~5-10s |
| **Totale** | **~3-5 min** | **~2 min** |

### Sembra bloccato — è normale?

Il `run.sh` passa `-s -v` a pytest, quindi vedi i print live del fixture
(`[e2e] Booting stack...`, `[e2e] Stack is healthy. Yielding to tests.`).

Se non vedi niente da > 30s, apri un secondo terminale e ispeziona:

```bash
# Quali container ci sono e in che stato (healthy/starting/unhealthy)
docker compose --project-name cullis-e2e \
  -f tests/e2e/docker-compose.e2e.yml ps

# Logs del broker (se /healthz non risponde, qui vedi perché)
docker compose --project-name cullis-e2e \
  -f tests/e2e/docker-compose.e2e.yml logs -f broker

# Logs di un proxy
docker compose --project-name cullis-e2e \
  -f tests/e2e/docker-compose.e2e.yml logs -f proxy-alpha
```

Cause comuni di "sembra bloccato":
- **Build pip lenta**: la prima volta `pip install` dei requirements del
  broker scarica ~200MB di wheel. Pazienza.
- **Vault non si sigilla**: il broker aspetta che vault sia healthy. Se
  vault crasha (`logs vault`), il broker resta in `starting`.
- **Network broker_net già esistente** con la stessa subnet: scarica
  questa eventualità con `docker network ls | grep cullis_e2e`.

Il fixture ha un timeout di **180 secondi** per ogni health check. Se
nemmeno dopo 3 minuti il broker risponde a `/healthz`, il test fallisce
con `TimeoutError: broker did not become healthy within 180s` e i
container vengono smontati. Mai zombie.

### Modo manuale — pytest diretto

```bash
# Lancia tutta la suite e2e
pytest -m e2e -o addopts="" tests/e2e/

# Filtra per nome
pytest -m e2e -o addopts="" tests/e2e/ -k full_two_org
```

L'`-o addopts=""` serve a sovrascrivere il filtro `-m "not e2e"` impostato
in `pytest.ini`. Senza quello, pytest skippa tutti i test col marker e2e.

### Tenere lo stack su per debug

```bash
KEEP_E2E_STACK=1 tests/e2e/run.sh
```

Dopo il run, lo stack resta acceso. Puoi ispezionare:

```bash
docker compose --project-name cullis-e2e \
               -f tests/e2e/docker-compose.e2e.yml ps

docker compose --project-name cullis-e2e \
               -f tests/e2e/docker-compose.e2e.yml logs broker

# Apri il broker direttamente:
curl http://localhost:18000/healthz
curl http://localhost:18000/readyz

# Apri i proxy:
curl http://localhost:19100/health  # alpha
curl http://localhost:19101/health  # beta
```

Quando hai finito:

```bash
docker compose --project-name cullis-e2e \
               -f tests/e2e/docker-compose.e2e.yml down -v
```

---

## Cosa testa precisamente

`tests/e2e/test_full_flow.py::test_full_two_org_message_exchange`:

| Step | Operazione | Endpoint reale |
|---|---|---|
| 1 | Genera invite token alpha | `POST /v1/admin/invites` (X-Admin-Secret) |
| 2 | Genera invite token beta  | idem |
| 3 | proxy-alpha registra org "alpha" + crea agent "buyer" | `setup_proxy_org.py` (in container) → `POST /v1/onboarding/join` + `AgentManager.create_agent` + binding auto-approve |
| 4 | proxy-beta registra org "beta" + crea agent "seller"  | idem |
| 5 | Admin approva entrambe le org                          | `POST /v1/admin/orgs/alpha/approve` + idem beta |
| 6 | alpha-buyer fa discovery cross-org per "procurement.read" | `POST /v1/egress/discover` su proxy-alpha |
| 7 | Verifica che beta-seller sia visibile                  | assert `beta.agent_id in discovered_ids` |
| 8 | alpha-buyer apre sessione verso beta-seller            | `POST /v1/egress/sessions` su proxy-alpha |
| 9 | beta-seller accetta la sessione pending                | `POST /v1/egress/sessions/{id}/accept` su proxy-beta |
| 10 | alpha-buyer manda un messaggio E2E con marker noto    | `POST /v1/egress/send` su proxy-alpha |
| 11 | beta-seller poll per il messaggio                     | `GET /v1/egress/messages/{id}` su proxy-beta |
| 12 | Verifica che il payload decriptato sia identico       | assert su `payload["marker"]`, `payload["items"]` |

Altri test inclusi:

- `test_invite_token_invalid_is_rejected` — invite token finto deve fallire
- `test_admin_invite_requires_admin_secret` — admin endpoint deve respingere
  chiamate senza header `X-Admin-Secret` valido

---

## Cosa NON testa (ancora)

Cose lasciate fuori dall'MVP, da aggiungere se ti servono per coprire
regression specifiche:

- **Reply path**: oggi è solo monodirezionale (alpha → beta). Se rompi il
  flusso beta → alpha non te ne accorgi.
- **Audit log hash chain verification**: il test non chiama `verify_chain()`
  alla fine.
- **RFQ broadcast** (`POST /v1/broker/rfq`).
- **Transaction tokens** (`POST /v1/auth/token/transaction`).
- **Graceful shutdown**: il fixture fa `down -v` brutale, non testa il drain
  watcher dell'item 4.
- **Cert rotation**.
- **OIDC role mapping** (item 1) — quello è coperto dai test mock-based.

---

## Architettura (perché è scritto così)

### Scelta 1 — script Python `setup_proxy_org.py` dentro al container

Il modo intuitivo per registrare un'org tramite il proxy sarebbe usare la
dashboard HTML del proxy. Ma significa fare scraping del CSRF token, gestire
form-encoded POST con cookie session, parsare l'HTML della response per
estrarre l'API key — tutto fragile.

L'alternativa scelta: uno script Python (`tests/e2e/scripts/setup_proxy_org.py`)
che viene **mountato come volume** nei container proxy e invocato via
`docker compose exec`. Riusa direttamente le funzioni Python del proxy
(`set_config`, `generate_org_ca`, `AgentManager.create_agent`) — gli stessi
moduli che chiama la dashboard. Il test runner lo invoca e parsa il JSON
che lo script stampa su stdout.

Pro:
- Niente HTML scraping
- Esercita il **vero** path produzione (stessi moduli, stesso DB, stessa CA)
- Se cambia il dashboard HTML il test continua a funzionare

Contro:
- Lo script vive in `tests/e2e/scripts/` e va tenuto allineato con
  l'evoluzione di `mcp_proxy.dashboard.router.generate_org_ca` e
  `mcp_proxy.egress.agent_manager.AgentManager.create_agent`. Se cambi la
  signature di una di queste funzioni, lo script va aggiornato.

### Scelta 2 — porte alte (18xxx / 19xxx) e project name dedicato

Lo stack e2e usa porte completamente separate dal compose principale per
non confliggere col tuo dev environment:

| Servizio   | Porta dev (compose principale) | Porta e2e |
|---|---|---|
| broker     | 8000                            | 18000     |
| proxy A    | 9100                            | 19100     |
| proxy B    | n/a                             | 19101     |
| nginx HTTPS| 8443                            | (non esposto) |

Più `--project-name cullis-e2e`: tutti i container, volumi e network sono
prefissati `cullis-e2e_*` e cancellati interamente da `down -v`. Niente
collisione né con un dev stack già in esecuzione né con un altro test e2e
parallelo (anche se non lo facciamo, almeno è isolato).

### Scelta 3 — niente nginx HTTPS davanti al broker

Lo stack e2e parla con il broker su `http://localhost:18000` direttamente.
Niente nginx, niente self-signed cert, niente `verify=False`. Motivo: il
test verifica il flusso applicativo (auth, sessione, messaggio E2E), non
la terminazione TLS. E significa anche che `BROKER_PUBLIC_URL` è vuoto
nel `.env` del broker, quindi `build_htu()` deriva l'URL dalla request →
zero rischio del foot-gun `htu mismatch`.

### Scelta 4 — `BROKER_PUBLIC_URL=""` esplicito

Documentato sopra, ma vale ribadirlo: nel compose e2e settiamo
`BROKER_PUBLIC_URL: ""`. Questo è la stessa difesa applicata in
`tests/conftest.py` per i test unit. Senza, un dev con
`BROKER_PUBLIC_URL=https://localhost:8443` nel `.env` locale vedrebbe il
test fallire con `Invalid DPoP proof: htu mismatch`.

---

## Troubleshooting

**`pytest` skippa tutti i test e2e**

Stai dimenticando il flag. Usa `tests/e2e/run.sh` o `pytest -m e2e -o addopts=""`.

**`docker compose up` fallisce con "port already allocated"**

Hai un altro stack `cullis-e2e` lasciato in piedi (KEEP_E2E_STACK), oppure
qualcuno sta usando 18000/19100/19101. Diagnostica:

```bash
docker compose --project-name cullis-e2e -f tests/e2e/docker-compose.e2e.yml ps
docker compose --project-name cullis-e2e -f tests/e2e/docker-compose.e2e.yml down -v
```

**`broker did not become healthy within 180s`**

Il broker non sta passando il proprio `/healthz`. Logs:

```bash
docker compose --project-name cullis-e2e -f tests/e2e/docker-compose.e2e.yml logs broker
```

Cause comuni: postgres health timeout, vault sealed, KMS bootstrap failure.

**`setup_proxy_org.py failed in proxy-alpha`**

Lo script helper ha fallito dentro al container. Il messaggio di errore
include sia stdout che stderr. Cause comuni:
- Broker non raggiungibile via DNS interno (`http://broker:8000`) → controlla
  che proxy-alpha sia sulla rete `cullis_e2e_net`
- Invite token già usato (DB persistente da run precedente) → assicurati di
  fare `down -v` prima
- `mcp_proxy.dashboard.router.generate_org_ca` ha cambiato signature →
  aggiorna lo script

**`htu mismatch`**

Non dovrebbe più succedere visto che `BROKER_PUBLIC_URL=""` nel compose
e2e. Se succede, vedi `docs/ops-runbook.md` sezione "Common pitfalls".

---

## Estendere il test

Vuoi coprire il reply path beta → alpha? Aggiungi questi step in fondo a
`test_full_two_org_message_exchange` dopo lo step 12:

```python
reply_payload = {"kind": "purchase_order_ack", "marker": "e2e-mvp-002", "ok": True}
await send_message(
    proxy_beta_url, beta.api_key,
    session_id=session_id,
    payload=reply_payload,
    recipient_agent_id=alpha.agent_id,
)
ack = await wait_for_message_with_payload(
    proxy_alpha_url, alpha.api_key,
    session_id=session_id,
    expected_marker_key="marker",
    expected_marker_value="e2e-mvp-002",
)
assert ack["payload"]["ok"] is True
```

Per RFQ broadcast e transaction tokens devi aggiungere un endpoint
helper analogo a quelli in `tests/e2e/helpers/e2e_messaging.py` — il
proxy egress non li espone ancora come API "interna", quindi serve
chiamare gli endpoint del broker direttamente o aggiungere wrapper
nel proxy.

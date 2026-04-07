"""
Cullis — Standalone Buyer Console

A FastAPI web app that runs on a separate VM from the broker.
Provides a chat UI where a human interacts with a buyer LLM agent
that uses Cullis broker tools (discover, open_session, send, poll).

Reads agent credentials from HashiCorp Vault; connects to a REMOTE broker.
"""
import asyncio
import json
import logging
import os
import sys
import time
from dataclasses import dataclass, field

import httpx
import uvicorn
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

# ── SDK import (copied into /app inside the container) ──────────────────────
sys.path.insert(0, "/app")
from agents.sdk import BrokerClient  # noqa: E402

# ── Configuration ───────────────────────────────────────────────────────────

BROKER_URL = os.environ.get("BROKER_URL", "https://broker.cullis.io:8443")
VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://127.0.0.1:8200")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN", "")
ANTHROPIC_API_KEY = os.environ.get("ANTHROPIC_API_KEY", "")
ORG_ID = os.environ.get("ORG_ID", "buyer-org")
AGENT_ID = os.environ.get("AGENT_ID", "buyer-agent")
LLM_MODEL = os.environ.get("LLM_MODEL", "claude-sonnet-4-6")

_log = logging.getLogger("cullis.buyer")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(levelname)s %(message)s")

# ── Background polling for incoming sessions ──────────────────────────────

async def _background_poller():
    """Poll the broker every 5s for pending sessions and new messages."""
    while True:
        await asyncio.sleep(5)
        try:
            if not _session or not _session.broker or not _session.broker.token:
                continue
            if _session.is_processing:
                continue

            broker = _session.broker

            # Check for pending incoming sessions
            try:
                sessions_list = broker.list_sessions()
                for s in sessions_list:
                    sid = s["session_id"]
                    if (s["status"] == "pending"
                            and s["target_agent_id"] == _session.agent_id
                            and sid not in _session.all_sessions):
                        initiator = s["initiator_agent_id"]
                        org = s["initiator_org_id"]
                        _session.messages.append(ConsoleMessage(
                            role="system",
                            content=f"Incoming session request from {initiator} ({org}). "
                                    f"Ask the agent to accept it or use check_pending_sessions.",
                        ))
            except Exception:
                pass

            # Check for new messages on all active sessions
            for active in list(_session.all_sessions.values()):
                try:
                    messages = broker.poll(active.session_id, after=active.last_seq)
                    for m in messages:
                        active.last_seq = max(active.last_seq, m.get("seq", active.last_seq))
                        text = m.get("payload", {}).get("text", json.dumps(m.get("payload", {})))
                        sender = m.get("sender_agent_id", "unknown")
                        active.received_messages.append({"from": sender, "text": text})
                        _session.messages.append(ConsoleMessage(
                            role="system",
                            content=f"[Message from {sender}]: {text}",
                        ))
                except Exception:
                    pass

        except Exception:
            pass


@asynccontextmanager
async def _lifespan(app):
    global _polling_task
    _polling_task = asyncio.create_task(_background_poller())
    yield
    _polling_task.cancel()
    try:
        await _polling_task
    except asyncio.CancelledError:
        pass


# ── FastAPI app ─────────────────────────────────────────────────────────────

app = FastAPI(title="Cullis Buyer Console", lifespan=_lifespan)

templates = Jinja2Templates(directory=os.path.join(os.path.dirname(__file__), "templates"))


# ── Data models ─────────────────────────────────────────────────────────────

@dataclass
class ConsoleMessage:
    role: str           # "human", "assistant", "system", "tool"
    content: str
    tool_name: str | None = None


@dataclass
class ActiveSession:
    """A single broker session with a remote agent."""
    session_id: str
    peer_agent_id: str
    peer_org_id: str
    role: str  # "initiator" or "responder"
    last_seq: int = -1
    received_messages: list = field(default_factory=list)  # messages from background poller


@dataclass
class BuyerSession:
    org_id: str
    agent_id: str
    broker: BrokerClient | None = None
    active_session: ActiveSession | None = None  # currently selected session
    all_sessions: dict[str, ActiveSession] = field(default_factory=dict)  # session_id -> ActiveSession
    messages: list[ConsoleMessage] = field(default_factory=list)
    llm_conversation: list[dict] = field(default_factory=list)
    is_processing: bool = False


# Single global session (one buyer per VM)
_session: BuyerSession | None = None
_polling_task: asyncio.Task | None = None


# ── Vault helper ────────────────────────────────────────────────────────────

async def _read_vault_secret(path: str) -> dict:
    """Read a KV-v2 secret from HashiCorp Vault."""
    async with httpx.AsyncClient() as client:
        resp = await client.get(
            f"{VAULT_ADDR}/v1/{path}",
            headers={"X-Vault-Token": VAULT_TOKEN},
        )
        resp.raise_for_status()
        return resp.json()["data"]["data"]


# ── Anthropic tool definitions ──────────────────────────────────────────────

BUYER_TOOLS = [
    {
        "name": "discover_suppliers",
        "description": (
            "Search the Cullis federated trust network for supplier agents. "
            "Use 'q' for free-text search across agent names, descriptions, org names. "
            "Use 'capabilities' to filter by specific capabilities. "
            "Use 'org_id' to filter by organization. "
            "Use 'pattern' for glob matching on agent_id (e.g. 'chipfactory::*'). "
            "At least one parameter is required. Use q='*' to list all agents."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "q": {
                    "type": "string",
                    "description": "Free-text search across agent name, description, org, agent_id. Use '*' to list all.",
                },
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Filter by capabilities, e.g. ['order.write', 'manufacturing']",
                },
                "org_id": {
                    "type": "string",
                    "description": "Filter by organization ID, e.g. 'chipfactory'",
                },
                "pattern": {
                    "type": "string",
                    "description": "Glob pattern on agent_id, e.g. 'chipfactory::*'",
                },
            },
        },
    },
    {
        "name": "open_session",
        "description": (
            "Open a trusted, policy-evaluated session with a supplier agent "
            "via the Cullis broker. Both organisations' policies are checked."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "target_agent_id": {"type": "string", "description": "The supplier agent ID"},
                "target_org_id": {"type": "string", "description": "The supplier organisation ID"},
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Capabilities requested for this session",
                },
            },
            "required": ["target_agent_id", "target_org_id", "capabilities"],
        },
    },
    {
        "name": "send_message_to_supplier",
        "description": (
            "Send a signed and E2E-encrypted message to the supplier through "
            "the active Cullis session. The message is cryptographically signed "
            "with your private key and encrypted with the supplier's public key."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "message": {
                    "type": "string",
                    "description": "The message text to send to the supplier",
                },
            },
            "required": ["message"],
        },
    },
    {
        "name": "check_supplier_responses",
        "description": (
            "Check if the supplier has sent any new messages in the active session. "
            "Messages are E2E-encrypted and will be decrypted with your private key."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "check_pending_sessions",
        "description": (
            "Check if any other agents on the Cullis network have requested "
            "a session with you. Returns a list of pending session requests "
            "that you can accept."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
    {
        "name": "accept_session",
        "description": (
            "Accept an incoming session request from another agent. "
            "This makes the session active so you can exchange messages."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "session_id": {
                    "type": "string",
                    "description": "The session ID to accept",
                },
            },
            "required": ["session_id"],
        },
    },
    {
        "name": "close_session",
        "description": (
            "Close the current active session with the supplier. "
            "Use this when the negotiation is complete or you want to end the conversation."
        ),
        "input_schema": {
            "type": "object",
            "properties": {},
        },
    },
]

BUYER_SYSTEM_PROMPT = """\
You are a procurement assistant for {org_id}, operating through the Cullis \
federated trust broker. You help your human operator purchase industrial \
components from verified suppliers on the network.

You have tools to:
1. discover_suppliers — search the Cullis network for matching suppliers
2. open_session — open a cryptographically secured session with a supplier
3. send_message_to_supplier — send E2E-encrypted messages to the supplier
4. check_supplier_responses — check for new replies from the supplier
5. check_pending_sessions — check for incoming session requests from other agents
6. accept_session — accept an incoming session request
7. close_session — close the current session when done

Workflow — Initiating:
- When the human asks for something, use discover_suppliers to find matching suppliers.
- Open a session with the best match.
- Negotiate on behalf of the human: ask for pricing, availability, delivery, payment terms.
- Report results back to the human and ask for confirmation before finalising.

Workflow — Receiving:
- Other agents may request sessions with you (e.g. a supplier proposing an offer).
- Use check_pending_sessions to see incoming requests.
- Use accept_session to accept them, then check_supplier_responses for their messages.
- Report incoming proposals to the human.

Always communicate with the human in their language. With suppliers, use English.

Important:
- Always check for supplier responses before reporting "no answer" — the supplier \
  agent may need a few seconds to respond.
- Be precise and professional in B2B communications.
- When the session with the supplier is waiting for a response, tell the human \
  you're waiting and they can check back.
"""


# ── Tool execution ──────────────────────────────────────────────────────────

def _execute_tool(session: BuyerSession, tool_name: str, tool_input: dict) -> str:
    """Execute a broker tool and return the result as a JSON string."""
    broker = session.broker
    if broker is None:
        return json.dumps({"error": "Broker not connected. Use /connect first."})

    try:
        if tool_name == "discover_suppliers":
            caps = tool_input.get("capabilities")
            org_id = tool_input.get("org_id")
            pattern = tool_input.get("pattern")
            q = tool_input.get("q")
            # If no filters provided, list all
            if not any([caps, org_id, pattern, q]):
                pattern = "*"
            agents = broker.discover(capabilities=caps, org_id=org_id, pattern=pattern, q=q)
            if not agents:
                return json.dumps({"result": "No suppliers found matching the search criteria."})
            # Format agent list for readability
            summary = []
            for a in agents:
                desc = a.get("description", "")
                caps_str = ", ".join(a.get("capabilities", []))
                line = f"- {a['display_name']} ({a['agent_id']}) org={a['org_id']}"
                if desc:
                    line += f" — {desc}"
                if caps_str:
                    line += f" [caps: {caps_str}]"
                summary.append(line)
            return json.dumps({"agents_found": len(agents), "agents": "\n".join(summary)})

        elif tool_name == "open_session":
            target_agent = tool_input["target_agent_id"]
            target_org = tool_input["target_org_id"]
            caps = tool_input.get("capabilities", ["order.write"])

            session_id = broker.open_session(target_agent, target_org, caps)
            active = ActiveSession(
                session_id=session_id,
                peer_agent_id=target_agent,
                peer_org_id=target_org,
                role="initiator",
            )
            session.all_sessions[session_id] = active
            session.active_session = active

            # Wait for session to be accepted (up to 30s)
            for _ in range(15):
                sessions_list = broker.list_sessions()
                s = next((x for x in sessions_list if x["session_id"] == session_id), None)
                if s and s["status"] == "active":
                    return json.dumps({"result": f"Session {session_id} is now active with {target_agent} ({target_org})."})
                time.sleep(2)

            return json.dumps({"result": f"Session {session_id} created but target has not accepted yet. Try check_supplier_responses later."})

        elif tool_name == "send_message_to_supplier":
            active = session.active_session
            if not active:
                return json.dumps({"error": "No active session. Use open_session or accept_session first."})
            message = tool_input["message"]
            payload = {"type": "order_negotiation", "text": message}
            broker.send(active.session_id, session.agent_id, payload,
                        recipient_agent_id=active.peer_agent_id)
            return json.dumps({"result": f"Message sent to {active.peer_agent_id}."})

        elif tool_name == "check_supplier_responses":
            active = session.active_session
            if not active:
                return json.dumps({"error": "No active session."})
            # Read from background poller buffer first
            if active.received_messages:
                texts = list(active.received_messages)
                active.received_messages.clear()
                return json.dumps({"result": texts})
            # Fallback: try a direct poll
            messages = broker.poll(active.session_id, after=active.last_seq)
            if not messages:
                return json.dumps({"result": "No new messages from the supplier."})
            texts = []
            for m in messages:
                active.last_seq = max(active.last_seq, m.get("seq", active.last_seq))
                text = m.get("payload", {}).get("text", json.dumps(m.get("payload", {})))
                texts.append({"from": m.get("sender_agent_id", "unknown"), "text": text})
            return json.dumps({"result": texts})

        elif tool_name == "check_pending_sessions":
            sessions_list = broker.list_sessions()
            pending = [
                s for s in sessions_list
                if s["status"] == "pending"
                and s["target_agent_id"] == session.agent_id
            ]
            if not pending:
                return json.dumps({"result": "No pending session requests."})
            items = [
                {
                    "session_id": s["session_id"],
                    "from_agent": s["initiator_agent_id"],
                    "from_org": s["initiator_org_id"],
                    "capabilities": s.get("requested_capabilities", []),
                }
                for s in pending
            ]
            return json.dumps({"result": items})

        elif tool_name == "accept_session":
            sid = tool_input["session_id"]
            broker.accept_session(sid)
            # Look up session details
            sessions_list = broker.list_sessions()
            s = next((x for x in sessions_list if x["session_id"] == sid), None)
            if s:
                peer_agent = s["initiator_agent_id"]
                peer_org = s["initiator_org_id"]
            else:
                peer_agent = "unknown"
                peer_org = "unknown"
            active = ActiveSession(
                session_id=sid,
                peer_agent_id=peer_agent,
                peer_org_id=peer_org,
                role="responder",
            )
            session.all_sessions[sid] = active
            session.active_session = active
            return json.dumps({"result": f"Session {sid} accepted. Now active with {peer_agent} ({peer_org})."})

        elif tool_name == "close_session":
            active = session.active_session
            if not active:
                return json.dumps({"error": "No active session to close."})
            broker.close_session(active.session_id)
            closed_peer = active.peer_agent_id
            del session.all_sessions[active.session_id]
            session.active_session = None
            return json.dumps({"result": f"Session with {closed_peer} closed successfully."})

        else:
            return json.dumps({"error": f"Unknown tool: {tool_name}"})

    except Exception as e:
        _log.exception("Tool execution error: %s", tool_name)
        return json.dumps({"error": str(e)})


# ── LLM interaction with tool loop ─────────────────────────────────────────

def _call_llm_with_tools(session: BuyerSession, user_message: str) -> str:
    """Call Claude with tools, execute tool calls in a loop, return final text."""
    import anthropic

    if not ANTHROPIC_API_KEY:
        return "Error: ANTHROPIC_API_KEY not configured."

    client = anthropic.Anthropic(api_key=ANTHROPIC_API_KEY)
    system = BUYER_SYSTEM_PROMPT.format(org_id=session.org_id)

    session.llm_conversation.append({"role": "user", "content": user_message})
    messages = list(session.llm_conversation)

    max_iterations = 10

    for _ in range(max_iterations):
        response = client.messages.create(
            model=LLM_MODEL,
            max_tokens=2048,
            system=system,
            tools=BUYER_TOOLS,
            messages=messages,
        )

        # Collect text and tool_use blocks
        text_parts = []
        tool_calls = []
        for block in response.content:
            if block.type == "text":
                text_parts.append(block.text)
            elif block.type == "tool_use":
                tool_calls.append(block)

        if not tool_calls:
            # No more tools — final response
            final_text = "\n".join(text_parts)
            session.llm_conversation.append({"role": "assistant", "content": response.content})
            return final_text

        # Add assistant message with all content blocks
        session.llm_conversation.append({"role": "assistant", "content": response.content})
        messages = list(session.llm_conversation)

        # Execute each tool and add results
        tool_results = []
        for tc in tool_calls:
            session.messages.append(ConsoleMessage(
                role="tool",
                content=f"Calling {tc.name}...",
                tool_name=tc.name,
            ))
            result = _execute_tool(session, tc.name, tc.input)
            session.messages.append(ConsoleMessage(
                role="tool",
                content=f"{tc.name} -> {result}",
                tool_name=tc.name,
            ))
            tool_results.append({
                "type": "tool_result",
                "tool_use_id": tc.id,
                "content": result,
            })

        session.llm_conversation.append({"role": "user", "content": tool_results})
        messages = list(session.llm_conversation)

    return "Reached maximum tool iterations. Please try again."


# ── Routes ──────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Serve the buyer console chat UI."""
    connected = _session is not None and _session.broker is not None and _session.broker.token is not None
    msgs = _session.messages if _session else []
    return templates.TemplateResponse(
        request=request, name="console.html", context={
            "org_id": ORG_ID,
            "agent_id": AGENT_ID,
            "connected": connected,
            "messages": msgs,
        }
    )


@app.post("/connect")
async def connect():
    """Read cert+key from Vault, create BrokerClient, login to remote broker."""
    global _session

    try:
        # Read credentials from Vault
        org_ca_secret = await _read_vault_secret("secret/data/org-ca")
        agent_secret = await _read_vault_secret("secret/data/agent")

        ca_cert_pem = org_ca_secret["ca_cert_pem"]
        cert_pem = agent_secret["cert_pem"]
        key_pem = agent_secret["private_key_pem"]

        _log.info("Loaded credentials from Vault for %s/%s", ORG_ID, AGENT_ID)

        # Create BrokerClient and authenticate
        broker = BrokerClient(BROKER_URL, verify_tls=False)

        try:
            broker.register(AGENT_ID, ORG_ID, AGENT_ID, ["order.write", "procurement"])
        except Exception:
            pass  # Already registered

        broker.login_from_pem(AGENT_ID, ORG_ID, cert_pem, key_pem)
        _log.info("Authenticated to broker at %s", BROKER_URL)

        _session = BuyerSession(
            org_id=ORG_ID,
            agent_id=AGENT_ID,
            broker=broker,
        )
        _session.messages.append(ConsoleMessage(
            role="system",
            content=f"Connected as {AGENT_ID} ({ORG_ID}) to broker at {BROKER_URL}.",
        ))

        return JSONResponse({"status": "connected", "agent_id": AGENT_ID, "org_id": ORG_ID})

    except Exception as e:
        _log.exception("Connect failed")
        return JSONResponse({"status": "error", "detail": str(e)}, status_code=500)


@app.post("/send")
async def send(request: Request):
    """Receive human message, call Claude with tools, execute tools, return reply."""
    global _session

    if not _session or not _session.broker:
        return JSONResponse({"error": "Not connected to broker"}, status_code=400)

    form = await request.form()
    user_msg = str(form.get("message", "")).strip()
    if not user_msg:
        return JSONResponse({"error": "Empty message"}, status_code=400)

    if _session.is_processing:
        return JSONResponse({"error": "Already processing a request"}, status_code=429)

    _session.is_processing = True
    _session.messages.append(ConsoleMessage(role="human", content=user_msg))

    try:
        reply = _call_llm_with_tools(_session, user_msg)
        _session.messages.append(ConsoleMessage(role="assistant", content=reply))
    except Exception as e:
        _log.exception("LLM error")
        reply = f"Error: {e}"
        _session.messages.append(ConsoleMessage(role="system", content=reply))
    finally:
        _session.is_processing = False

    return JSONResponse({"reply": reply, "message_count": len(_session.messages)})


@app.get("/messages")
async def get_messages():
    """Return conversation history as JSON (for HTMX polling)."""
    if not _session:
        return JSONResponse({"messages": [], "connected": False, "processing": False})

    active = _session.active_session
    msgs = [
        {"role": m.role, "content": m.content, "tool_name": m.tool_name}
        for m in _session.messages
    ]
    return JSONResponse({
        "messages": msgs,
        "connected": _session.broker is not None and _session.broker.token is not None,
        "processing": _session.is_processing,
        "session_id": active.session_id if active else None,
        "target": active.peer_agent_id if active else None,
        "session_count": len(_session.all_sessions),
    })


@app.post("/disconnect")
async def disconnect():
    """Close session and broker client."""
    global _session

    if _session and _session.broker:
        for active in _session.all_sessions.values():
            try:
                _session.broker.close_session(active.session_id)
            except Exception:
                pass
        try:
            _session.broker.close()
        except Exception:
            pass

    _session = None
    return JSONResponse({"status": "disconnected"})


# ── Entrypoint ──────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")))

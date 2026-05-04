import { useEffect, useReducer, useState } from 'react';
import { MessageList } from './MessageList';
import { MessageInput } from './MessageInput';
import { ApiError, chatCompletionStream, initSession } from '../lib/api';
import type { ChatMessage } from '../lib/types';
import '../styles/chat-window.css';

/** State machine. v0.1 single thread + SSE streaming. */
interface ChatState {
  messages: ChatMessage[];
  status: 'idle' | 'sending';
  error: string | null;
  /** Bump to push a draft into the input box (from hint clicks). */
  draft?: string;
}

type Action =
  | { type: 'append'; message: ChatMessage }
  | { type: 'patch'; id: string; patch: Partial<ChatMessage> }
  | { type: 'sending' }
  | { type: 'idle' }
  | { type: 'error'; message: string }
  | { type: 'set_draft'; text: string }
  | { type: 'clear_draft' };

function reducer(state: ChatState, action: Action): ChatState {
  switch (action.type) {
    case 'append':
      return { ...state, messages: [...state.messages, action.message] };
    case 'patch':
      return {
        ...state,
        messages: state.messages.map((m) =>
          m.id === action.id ? { ...m, ...action.patch } : m,
        ),
      };
    case 'sending':
      return { ...state, status: 'sending', error: null };
    case 'idle':
      return { ...state, status: 'idle' };
    case 'error':
      return { ...state, status: 'idle', error: action.message };
    case 'set_draft':
      return { ...state, draft: action.text };
    case 'clear_draft':
      return { ...state, draft: undefined };
  }
}

const INITIAL: ChatState = { messages: [], status: 'idle', error: null };

const DEFAULT_MODEL = 'claude-haiku-4-5';

function newId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

export default function ChatWindow() {
  const [state, dispatch] = useReducer(reducer, INITIAL);
  const [sessionReady, setSessionReady] = useState(false);

  // Session init at mount — issues the HttpOnly cookie. Without this,
  // every /api/proxy/* call returns 401.
  useEffect(() => {
    let cancelled = false;
    initSession()
      .then(() => !cancelled && setSessionReady(true))
      .catch((err) => {
        if (cancelled) return;
        const reason = err instanceof ApiError
          ? (err.payload as { message?: string })?.message ?? `HTTP ${err.status}`
          : err instanceof Error
            ? err.message
            : String(err);
        dispatch({ type: 'error', message: `session_init: ${reason}` });
      });
    return () => {
      cancelled = true;
    };
  }, []);

  async function send(text: string) {
    if (!sessionReady) {
      dispatch({ type: 'error', message: 'Session is not ready yet — try again in a moment.' });
      return;
    }
    const userMsg: ChatMessage = {
      id: newId('m'),
      role: 'user',
      content: text,
      createdAt: Date.now(),
    };
    dispatch({ type: 'append', message: userMsg });

    const placeholder: ChatMessage = {
      id: newId('m'),
      role: 'assistant',
      content: '',
      createdAt: Date.now(),
      pending: true,
    };
    dispatch({ type: 'append', message: placeholder });
    dispatch({ type: 'sending' });

    const accumulator = { content: '' };
    let lastFlush = 0;
    const FLUSH_MS = 60;

    function flush(force = false) {
      const now = Date.now();
      if (!force && now - lastFlush < FLUSH_MS) return;
      lastFlush = now;
      dispatch({ type: 'patch', id: placeholder.id, patch: { content: accumulator.content } });
    }

    try {
      const history = [...state.messages, userMsg].map((m) => ({ role: m.role, content: m.content }));
      const events = chatCompletionStream({
        model: DEFAULT_MODEL,
        messages: history,
      });

      let traceId: string | undefined;
      for await (const ev of events) {
        if (ev.kind === 'chunk') {
          const delta = ev.chunk.choices?.[0]?.delta?.content ?? '';
          if (delta) {
            accumulator.content += delta;
            flush();
          }
          if (!traceId) traceId = ev.chunk.id;
          if (ev.chunk.cullis_audit) {
            dispatch({
              type: 'patch',
              id: placeholder.id,
              patch: {
                trace_id: ev.chunk.cullis_audit.trace_id,
                audit: ev.chunk.cullis_audit,
              },
            });
          }
        } else if (ev.kind === 'audit') {
          dispatch({
            type: 'patch',
            id: placeholder.id,
            patch: { trace_id: ev.audit.trace_id, audit: ev.audit },
          });
        } else if (ev.kind === 'done') {
          break;
        }
        // tool_start / tool_end will be wired into the audit panel in commit 7.
      }

      flush(true);
      dispatch({
        type: 'patch',
        id: placeholder.id,
        patch: { pending: false, trace_id: traceId },
      });
      dispatch({ type: 'idle' });
    } catch (err) {
      const reason = err instanceof ApiError
        ? `${err.status} ${JSON.stringify(err.payload).slice(0, 200)}`
        : err instanceof Error
          ? err.message
          : String(err);
      dispatch({ type: 'patch', id: placeholder.id, patch: { content: '(no answer)', pending: false } });
      dispatch({ type: 'error', message: reason });
    }
  }

  return (
    <div className="chat-shell">
      {state.error ? (
        <div className="chat-error" role="alert">
          <strong>error</strong>
          {state.error}
        </div>
      ) : null}

      <MessageList
        messages={state.messages}
        isEmpty={state.messages.length === 0}
        onHintClick={(t) => dispatch({ type: 'set_draft', text: t })}
      />

      <MessageInput
        onSend={send}
        disabled={!sessionReady}
        isSending={state.status === 'sending'}
        draft={state.draft}
        onDraftConsumed={() => dispatch({ type: 'clear_draft' })}
      />

      <p className="chat-foot">
        Bearer · cookie HttpOnly · CSP nonce-locked · markdown sanitised via DOMPurify
      </p>
    </div>
  );
}

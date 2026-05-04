import { MarkdownView } from './MarkdownView';
import type { ChatMessage } from '../lib/types';

interface Props {
  message: ChatMessage;
}

/**
 * One chat turn — user or assistant.
 *
 * Assistant content is rendered through `MarkdownView` (DOMPurify +
 * marked + lazy Shiki). User content is plain text — escaped by React.
 */
export function Message({ message }: Props) {
  const isUser = message.role === 'user';
  const ts = new Date(message.createdAt);
  const tsLabel = ts.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' });

  return (
    <article className={`msg msg-${message.role}`} aria-label={`${message.role} message`}>
      <header className="msg-meta">
        <span className={`msg-role ${isUser ? 'msg-role-user' : ''}`}>
          {isUser ? 'mario' : 'cullis'}
        </span>
        <span className="msg-folio">
          <em>{tsLabel}</em>
          {message.trace_id ? <> · {message.trace_id}</> : null}
        </span>
      </header>
      {isUser ? (
        <div className="msg-body msg-body-user">{message.content}</div>
      ) : (
        <div className={`msg-body msg-body-assistant${message.pending ? ' msg-pending' : ''}`}>
          {message.content.length > 0 ? (
            <MarkdownView text={message.content} pending={message.pending} />
          ) : (
            <span className="msg-empty-pending" aria-label="awaiting first chunk">
              <em>thinking</em>
            </span>
          )}
        </div>
      )}
    </article>
  );
}

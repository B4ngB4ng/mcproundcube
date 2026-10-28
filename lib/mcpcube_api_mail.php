<?php

declare(strict_types=1);

/**
 * Mail API surface exposed to sandboxed scripts as `$mail`. Every method
 * checks its own OAuth scope against the calling agent before touching
 * IMAP/SMTP. Every method here is public; nothing else on this class is, so
 * the reflection-based dispatch in mcpcube_sandbox can never call anything
 * unintended.
 *
 * Integration note: list/search/flag/move/create/delete folder operations
 * use rcube_imap's documented public API (list_folders_subscribed,
 * folder_status, search, get_message_headers, set_flag/unset_flag,
 * move_message, create_folder, delete_folder, clear_folder) and
     * sendMessage() uses the bundled Mail_mime + rcmail::smtp_init()/rcube_smtp
     * and Roundcube's sendmail helper to store a copy in the Sent mailbox.
 * These calls were written against Roundcube 1.7's documented plugin API
 * surface but were not executed against a live instance while building this
 * plugin - smoke-test every method (especially sendMessage) against a real
 * Roundcube 1.7.3 install before relying on it in production.
 */
final class mcpcube_api_mail
{
    private const MAX_ATTACHMENT_BYTES = 20971520;

    public function __construct(private readonly mcpcube_auth_context $ctx)
    {
    }

    /** @return list<array{name: string, unread: int, total: int, delimiter: string}> */
    public function listFolders(): array
    {
        $this->require_scope('mail.read');
        $storage = $this->ctx->rcmail()->get_storage();
        $delimiter = (string) $storage->get_hierarchy_delimiter();
        $result = [];

        foreach ($storage->list_folders_subscribed() as $folder) {
            $status = $storage->folder_status($folder) ?: [];
            $result[] = [
                'name' => $folder,
                'unread' => (int) ($status['unseen'] ?? 0),
                'total' => (int) ($status['messages'] ?? 0),
                'delimiter' => $delimiter,
            ];
        }

        return $result;
    }

    /** @return list<array<string, mixed>> */
    public function listMessages(string $folder = 'INBOX', int $limit = 100, int $offset = 0): array
    {
        $this->require_scope('mail.read');
        $limit = max(1, min(200, $limit));
        $offset = max(0, $offset);

        $storage = $this->ctx->rcmail()->get_storage();
        $index = $storage->search($folder, 'ALL');
        $uids = array_reverse($index->get());
        $slice = array_slice($uids, $offset, $limit);

        $messages = [];
        foreach ($slice as $uid) {
            $header = $storage->get_message_headers($uid, $folder);
            if ($header) {
                $messages[] = $this->summarize_header($header, $folder);
            }
        }

        return $messages;
    }

    /** @return array<string, mixed> */
    public function getMessage(int $uid, string $folder = 'INBOX'): array
    {
        $this->require_scope('mail.read');
        $message = new rcube_message((string) $uid, $folder);

        if (empty($message->headers)) {
            throw new mcpcube_tool_error("Message {$uid} was not found in {$folder}.");
        }

        $attachments = [];
        foreach ($message->attachments as $part) {
            $attachments[] = [
                'filename' => (string) ($part->filename ?? '(unnamed)'),
                'mimetype' => (string) ($part->mimetype ?? 'application/octet-stream'),
                'size' => (int) ($part->size ?? 0),
                'part_id' => (string) ($part->mime_id ?? ''),
            ];
        }

        $bodyText = $message->first_text_part();
        if ($bodyText === null) {
            $html = $message->first_html_part();
            $bodyText = $html !== null ? trim(strip_tags($html)) : '';
        }

        return [
            'uid' => $uid,
            'folder' => $folder,
            'subject' => (string) $message->subject,
            'from' => (string) ($message->headers->from ?? ''),
            'to' => (string) ($message->headers->to ?? ''),
            'cc' => (string) ($message->headers->cc ?? ''),
            'date' => (string) ($message->headers->date ?? ''),
            'message_id' => (string) ($message->headers->messageID ?? ''),
            'body_text' => (string) $bodyText,
            'attachments' => $attachments,
        ];
    }

    /**
     * Raw attachment bytes, base64-encoded so the script can pass them to sendMessage.
     * Do not return this from the script when the file is large; pass it straight into sendMessage.
     *
     * @return array{filename: string, mimetype: string, size: int, part_id: string, content_base64: string}
     */
    public function getAttachment(int $uid, string $partId, string $folder = 'INBOX'): array
    {
        $this->require_scope('mail.read');
        $message = $this->load_message($uid, $folder);

        return $this->read_attachment($message, $partId);
    }

    /**
     * Send a copy of an existing message, including its attachments, without
     * pulling the file bytes back through the connector.
     *
     * @return array{status: string, to: string, subject: string, message_id: string, saved: bool, saved_to?: string, warning?: string, forwarded_uid: int, attachments: int}
     */
    public function forwardMessage(int $uid, string $folder, string $to, ?string $bodyText = null, ?string $subject = null): array
    {
        $this->require_scope('mail.read');
        $message = $this->load_message($uid, $folder);
        $files = [];
        foreach ($message->attachments as $part) {
            $partId = (string) ($part->mime_id ?? '');
            if ($partId === '') {
                continue;
            }
            $files[] = $this->read_attachment($message, $partId);
        }

        $originalSubject = (string) $message->subject;
        $fwdSubject = $subject !== null && trim($subject) !== ''
            ? $subject
            : (preg_match('/^\s*fwd:/i', $originalSubject) ? $originalSubject : 'Fwd: ' . $originalSubject);
        $quote = "---------- Forwarded message ----------\n"
            . 'From: ' . (string) ($message->headers->from ?? '') . "\n"
            . 'Date: ' . (string) ($message->headers->date ?? '') . "\n"
            . 'Subject: ' . $originalSubject . "\n"
            . 'To: ' . (string) ($message->headers->to ?? '') . "\n\n"
            . (string) ($message->first_text_part() ?? '');
        $body = trim((string) $bodyText);
        $body = $body === '' ? $quote : $body . "\n\n" . $quote;

        $sent = $this->sendMessage([
            'to' => $to,
            'subject' => $fwdSubject,
            'body_text' => $body,
            'attachments' => $files,
        ]);
        $sent['forwarded_uid'] = $uid;
        $sent['attachments'] = count($files);
        try {
            $sent['forwarded'] = $this->store_message_flag($uid, $folder, 'FORWARDED');
        } catch (Throwable $e) {
            $sent['forwarded'] = false;
        }
        if (!$sent['forwarded']) {
            $sent = $this->append_warning(
                $sent,
                'The message was forwarded, but the original was not marked Forwarded, so mail clients will not show it as forwarded.'
            );
        }

        return $sent;
    }

    /** @return list<array<string, mixed>> */
    public function searchMessages(string $query, string $folder = 'INBOX', int $limit = 50): array
    {
        $this->require_scope('mail.read');
        $limit = max(1, min(200, $limit));

        if (trim($query) === '') {
            throw new mcpcube_tool_error('searchMessages requires a non-empty query.');
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $escaped = str_replace(['\\', '"'], ['\\\\', '\\"'], $query);
        $index = $storage->search($folder, 'TEXT "' . $escaped . '"');
        $uids = array_slice(array_reverse($index->get()), 0, $limit);

        $messages = [];
        foreach ($uids as $uid) {
            $header = $storage->get_message_headers($uid, $folder);
            if ($header) {
                $messages[] = $this->summarize_header($header, $folder);
            }
        }

        return $messages;
    }

    /**
     * @param array{to: string, subject: string, cc?: string, bcc?: string, body_text?: string, body_html?: string, in_reply_to?: string, references?: string, reply_uid?: int, reply_folder?: string, attachments?: list<array{filename: string, mimetype?: string, content_base64: string}>} $message
     * @return array{status: string, to: string, subject: string, message_id: string, saved: bool, saved_to?: string, warning?: string, answered?: bool, answered_uid?: int, answered_folder?: string}
     */
    public function sendMessage(array $message): array
    {
        $this->require_scope('mail.write');

        $to = trim((string) ($message['to'] ?? ''));
        $subject = (string) ($message['subject'] ?? '');
        if ($to === '' || $subject === '') {
            throw new mcpcube_tool_error('sendMessage requires at least "to" and "subject".');
        }
        foreach (['to', 'subject', 'cc', 'bcc', 'in_reply_to', 'references', 'reply_folder'] as $field) {
            if (isset($message[$field]) && preg_match('/[\r\n]/', (string) $message[$field])) {
                throw new mcpcube_tool_error("sendMessage header '{$field}' must not contain line breaks.");
            }
        }
        if (array_key_exists('reply_uid', $message) && $message['reply_uid'] !== null && $message['reply_uid'] !== '') {
            if (!is_numeric($message['reply_uid']) || (int) $message['reply_uid'] <= 0) {
                throw new mcpcube_tool_error('sendMessage reply_uid must be a positive message uid.');
            }
        }

        $rcmail = $this->ctx->rcmail();
        $identity = $rcmail->user->get_identity();
        $from = is_array($identity) && !empty($identity['email']) ? (string) $identity['email'] : (string) $rcmail->user->get_username();
        if (!str_contains($from, '@') || str_ends_with(strtolower($from), '@localhost')) {
            throw new mcpcube_tool_error('This mailbox has no real From identity configured. Set a default identity in Roundcube Settings.');
        }

        $mime = new Mail_mime(['eol' => "\r\n"]);
        $mime->setParam('head_charset', 'UTF-8');
        $mime->setParam('text_charset', 'UTF-8');
        $mime->setParam('html_charset', 'UTF-8');

        if (!empty($message['body_text'])) {
            $mime->setTXTBody((string) $message['body_text']);
        }
        if (!empty($message['body_html'])) {
            $mime->setHTMLBody((string) $message['body_html']);
        }
        if (empty($message['body_text']) && empty($message['body_html'])) {
            $mime->setTXTBody('');
        }

        foreach ($this->normalize_attachments($message['attachments'] ?? []) as $file) {
            $added = $mime->addAttachment($file['content'], $file['mimetype'], $file['filename'], false);
            if ($added !== true) {
                throw new mcpcube_tool_error('Could not attach ' . $file['filename'] . '.');
            }
        }

        $headers = [
            'From' => $from,
            'To' => $to,
            'Subject' => $subject,
            'Date' => gmdate('r'),
            'Message-ID' => $rcmail->gen_message_id(),
            'X-Mailer' => (string) $rcmail->config->get('mcpcube_server_name', 'MCPcube'),
        ];
        if (!empty($message['cc'])) {
            $headers['Cc'] = (string) $message['cc'];
        }
        if (!empty($message['in_reply_to'])) {
            $headers['In-Reply-To'] = (string) $message['in_reply_to'];
        }
        if (!empty($message['references'])) {
            $headers['References'] = (string) $message['references'];
        }
        $mime->headers($headers);

        $recipients = [$to];
        if (!empty($message['cc'])) {
            $recipients[] = (string) $message['cc'];
        }
        if (!empty($message['bcc'])) {
            $recipients[] = (string) $message['bcc'];
        }

        $rcmail->smtp_init(false);
        if (!$rcmail->smtp->connect()) {
            $error = $rcmail->smtp->get_error();
            $detail = '';
            if (is_array($error)) {
                $detail = trim(implode(' ', array_map('strval', $error)));
            } elseif (is_string($error) && $error !== '') {
                $detail = $error;
            }
            $response = $rcmail->smtp->get_response();
            if (is_array($response) && $response !== []) {
                $detail = trim($detail . ' ' . implode(' ', array_map('strval', $response)));
            }
            throw new mcpcube_tool_error('Could not initialize the SMTP connection.' . ($detail !== '' ? ' ' . $detail : ''));
        }

        $headerText = $mime->txtHeaders();
        $bodyText = $mime->get();
        $sent = $rcmail->smtp->send_mail($from, $recipients, $headerText, $bodyText);
        $response = $rcmail->smtp->get_response();
        $rcmail->smtp->reset();

        if (!$sent) {
            throw new mcpcube_tool_error('The mail server rejected the message: ' . implode(' ', (array) $response));
        }

        // SMTP already accepted the message. Marking the original is best-effort
        // and must not turn a delivered reply into a failed send.
        $answered = $this->mark_original_answered($message);

        $result = [
            'status' => 'sent',
            'to' => $to,
            'subject' => $subject,
            'message_id' => $headers['Message-ID'],
            'saved' => false,
        ];

        if ($rcmail->config->get('no_save_sent_messages')) {
            $result['warning'] = 'The message was sent, but saving sent messages is disabled in Roundcube.';
            return $this->attach_answered($result, $answered);
        }

        $sentFolder = (string) $rcmail->config->get('sent_mbox');
        if ($sentFolder === '') {
            $result['warning'] = 'The message was sent, but no Sent mailbox is configured in Roundcube.';
            return $this->attach_answered($result, $answered);
        }

        // Use the same folder creation/subscription and IMAP APPEND path as
        // Roundcube's regular compose action. Do not report this as a send
        // failure: SMTP has already accepted the message and retrying could
        // deliver a duplicate.
        $sendmail = new rcmail_sendmail();
        if (!$sendmail->save_message($mime)) {
            $result['warning'] = "The message was sent, but its copy could not be saved in {$sentFolder}. Do not resend it.";
            return $this->attach_answered($result, $answered);
        }

        $result['saved'] = true;
        $result['saved_to'] = $sentFolder;

        return $this->attach_answered($result, $answered);
    }

    /** @return array<string, mixed> */
    public function moveMessage(int $uid, string $folder, string $targetFolder): array
    {
        $this->require_scope('mail.write');
        $storage = $this->ctx->rcmail()->get_storage();

        if (!$storage->move_message((string) $uid, $targetFolder, $folder)) {
            throw new mcpcube_tool_error("Could not move message {$uid} from {$folder} to {$targetFolder}.");
        }

        return ['status' => 'moved', 'uid' => $uid, 'from' => $folder, 'to' => $targetFolder];
    }

    /** @return array<string, mixed> */
    public function flagMessage(int $uid, string $folder, string $flag, bool $set = true): array
    {
        $this->require_scope('mail.write');
        $allowed = ['SEEN', 'FLAGGED', 'ANSWERED', 'DRAFT'];
        $flag = strtoupper($flag);
        if (!in_array($flag, $allowed, true)) {
            throw new mcpcube_tool_error('flag must be one of: ' . implode(', ', $allowed));
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $ok = $set
            ? $storage->set_flag((string) $uid, $flag, $folder)
            : $storage->unset_flag((string) $uid, $flag, $folder);
        if (!$ok) {
            throw new mcpcube_tool_error("Could not update flag {$flag} on message {$uid}.");
        }

        return ['status' => 'ok', 'uid' => $uid, 'flag' => $flag, 'set' => $set];
    }

    /** @return array<string, mixed> */
    public function createFolder(string $name, ?string $parent = null): array
    {
        $this->require_scope('mail.write');
        $storage = $this->ctx->rcmail()->get_storage();
        $delimiter = (string) $storage->get_hierarchy_delimiter();
        $fullName = $parent !== null && $parent !== '' ? $parent . $delimiter . $name : $name;

        if (!$storage->create_folder($fullName)) {
            throw new mcpcube_tool_error("Could not create folder {$fullName}.");
        }
        $storage->subscribe($fullName);

        return ['status' => 'created', 'name' => $fullName];
    }

    /**
     * Two-step delete: call once without $confirm to get a preview and a
     * confirmation_token; call again with confirm:true and that token to
     * actually delete.
     *
     * @param int|list<int> $uid
     * @return array<string, mixed>
     */
    public function deleteMessage(int|array $uid, string $folder = 'INBOX', bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('mail.delete');
        $uids = array_values(array_unique(array_map('intval', is_array($uid) ? $uid : [$uid])));
        if ($uids === []) {
            throw new mcpcube_tool_error('No message uid given.');
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $ids = array_map('strval', $uids);
        $op = 'delete_message:' . $folder;

        if (!$confirm) {
            $preview = [];
            foreach ($uids as $u) {
                $header = $storage->get_message_headers($u, $folder);
                $preview[] = $header
                    ? ['uid' => $u, 'subject' => (string) ($header->subject ?? '(no subject)'), 'from' => (string) ($header->from ?? '')]
                    : ['uid' => $u, 'subject' => '(not found)', 'from' => ''];
            }

            return [
                'status' => 'confirmation_required',
                'folder' => $folder,
                'preview' => $preview,
                'confirmation_token' => mcpcube_confirmation::issue($op, $ids, $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, $ids, $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token. Call deleteMessage again without confirm to get a fresh one.');
        }

        if (!$storage->delete_message($uids, $folder)) {
            throw new mcpcube_tool_error('Could not delete the message(s).');
        }

        return ['status' => 'deleted', 'uids' => $uids, 'folder' => $folder];
    }

    /** @return array<string, mixed> */
    public function emptyFolder(string $folder, bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('mail.delete');
        $storage = $this->ctx->rcmail()->get_storage();
        $status = $storage->folder_status($folder) ?: [];
        $count = (int) ($status['messages'] ?? 0);
        $op = 'empty_folder';

        if (!$confirm) {
            return [
                'status' => 'confirmation_required',
                'folder' => $folder,
                'message_count' => $count,
                'confirmation_token' => mcpcube_confirmation::issue($op, [$folder], $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, [$folder], $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token.');
        }

        if (!$storage->clear_folder($folder)) {
            throw new mcpcube_tool_error("Could not empty folder {$folder}.");
        }

        return ['status' => 'emptied', 'folder' => $folder, 'messages_removed' => $count];
    }

    /** @return array<string, mixed> */
    public function deleteFolder(string $name, bool $confirm = false, ?string $confirmationToken = null): array
    {
        $this->require_scope('mail.delete');
        $op = 'delete_folder';

        if (!$confirm) {
            return [
                'status' => 'confirmation_required',
                'folder' => $name,
                'confirmation_token' => mcpcube_confirmation::issue($op, [$name], $this->ctx->token_hash()),
            ];
        }

        if (!mcpcube_confirmation::verify($confirmationToken, $op, [$name], $this->ctx->token_hash())) {
            throw new mcpcube_tool_error('Invalid or expired confirmation_token.');
        }

        $storage = $this->ctx->rcmail()->get_storage();
        if (!$storage->delete_folder($name)) {
            throw new mcpcube_tool_error("Could not delete folder {$name}.");
        }

        return ['status' => 'deleted', 'folder' => $name];
    }

    private function load_message(int $uid, string $folder): rcube_message
    {
        $message = new rcube_message((string) $uid, $folder);
        if (empty($message->headers)) {
            throw new mcpcube_tool_error("Message {$uid} was not found in {$folder}.");
        }

        return $message;
    }

    /** @return array{filename: string, mimetype: string, size: int, part_id: string, content_base64: string} */
    private function read_attachment(rcube_message $message, string $partId): array
    {
        if (!preg_match('/^[0-9]+(?:\.[0-9]+)*$/', $partId)) {
            throw new mcpcube_tool_error('part_id must be a MIME part number such as 2 or 1.2.');
        }

        $part = $message->mime_parts[$partId] ?? null;
        if ($part === null) {
            throw new mcpcube_tool_error("Attachment part {$partId} was not found.");
        }

        $size = (int) ($part->size ?? 0);
        if ($size > self::MAX_ATTACHMENT_BYTES) {
            throw new mcpcube_tool_error('Attachment ' . $partId . ' is larger than 20 MB.');
        }

        $body = $message->get_part_body($partId, false);
        if (!is_string($body) || $body === '') {
            throw new mcpcube_tool_error("Could not read attachment part {$partId}.");
        }
        if (strlen($body) > self::MAX_ATTACHMENT_BYTES) {
            throw new mcpcube_tool_error('Attachment ' . $partId . ' is larger than 20 MB.');
        }

        $filename = (string) ($part->filename ?? '');
        if ($filename === '') {
            $filename = 'attachment-' . str_replace('.', '-', $partId);
        }

        return [
            'filename' => $this->safe_filename($filename),
            'mimetype' => (string) ($part->mimetype ?? 'application/octet-stream'),
            'size' => strlen($body),
            'part_id' => $partId,
            'content_base64' => base64_encode($body),
        ];
    }

    /**
     * @param mixed $attachments
     * @return list<array{filename: string, mimetype: string, content: string}>
     */
    private function normalize_attachments(mixed $attachments): array
    {
        if ($attachments === null || $attachments === []) {
            return [];
        }
        if (!is_array($attachments)) {
            throw new mcpcube_tool_error('attachments must be a list.');
        }

        $files = [];
        foreach ($attachments as $file) {
            if (!is_array($file)) {
                throw new mcpcube_tool_error('Each attachment must be an array with filename and content_base64.');
            }
            $encoded = (string) ($file['content_base64'] ?? '');
            $binary = base64_decode($encoded, true);
            if ($encoded === '' || $binary === false || $binary === '') {
                throw new mcpcube_tool_error('Attachment content_base64 is empty or not valid base64.');
            }
            if (strlen($binary) > self::MAX_ATTACHMENT_BYTES) {
                throw new mcpcube_tool_error('An attachment is larger than 20 MB.');
            }
            $mimetype = trim((string) ($file['mimetype'] ?? 'application/octet-stream'));
            if ($mimetype === '' || preg_match('/[\r\n]/', $mimetype)) {
                throw new mcpcube_tool_error('Attachment mimetype is invalid.');
            }
            $files[] = [
                'filename' => $this->safe_filename((string) ($file['filename'] ?? 'attachment')),
                'mimetype' => $mimetype,
                'content' => $binary,
            ];
        }

        return $files;
    }

    private function safe_filename(string $filename): string
    {
        $filename = str_replace(["\0", "\r", "\n", '/', '\\'], '', $filename);
        $filename = trim($filename);
        if ($filename === '' || $filename === '.' || $filename === '..') {
            $filename = 'attachment';
        }

        return mb_substr($filename, 0, 200);
    }

    private function require_scope(string $scope): void
    {
        if (!$this->ctx->has_scope($scope)) {
            throw new mcpcube_tool_error("This agent was not granted the '{$scope}' scope. Ask the user to re-pair with that scope enabled.");
        }
    }

    /**
     * Store the IMAP \Answered flag on the message this send is replying to.
     * Mail clients show the replied icon from that flag, not from In-Reply-To.
     *
     * @param array<string, mixed> $message
     * @return array{uid: int, folder: string, set: bool}|null Null when this send is not a reply
     */
    private function mark_original_answered(array $message): ?array
    {
        $replyUid = (isset($message['reply_uid']) && is_numeric($message['reply_uid']))
            ? (int) $message['reply_uid']
            : 0;
        $replyFolder = trim((string) ($message['reply_folder'] ?? ''));
        $messageId = trim((string) ($message['in_reply_to'] ?? ''));
        if ($replyUid <= 0 && $messageId === '') {
            return null;
        }

        try {
            if ($replyUid > 0) {
                $folder = $replyFolder !== '' ? $replyFolder : 'INBOX';
                if ($this->store_message_flag($replyUid, $folder, 'ANSWERED')) {
                    return ['uid' => $replyUid, 'folder' => $folder, 'set' => true];
                }
            }

            foreach ($this->find_messages_by_id($messageId, $replyFolder) as $hit) {
                if ($this->store_message_flag($hit['uid'], $hit['folder'], 'ANSWERED')) {
                    return ['uid' => $hit['uid'], 'folder' => $hit['folder'], 'set' => true];
                }
            }
        } catch (Throwable $e) {
            return ['uid' => $replyUid, 'folder' => $replyFolder, 'set' => false];
        }

        return ['uid' => $replyUid, 'folder' => $replyFolder, 'set' => false];
    }

    /**
     * @return list<array{uid: int, folder: string}>
     */
    private function find_messages_by_id(string $messageId, string $preferredFolder): array
    {
        $needle = trim($messageId, " \t<>");
        if ($needle === '' || preg_match('/[\r\n"\\\\]/', $needle)) {
            return [];
        }

        $criteria = 'HEADER Message-ID "' . $needle . '"';
        $storage = $this->ctx->rcmail()->get_storage();
        $folders = [];
        if ($preferredFolder !== '') {
            $folders[] = $preferredFolder;
        }
        if (!in_array('INBOX', $folders, true)) {
            $folders[] = 'INBOX';
        }
        foreach ($storage->list_folders_subscribed() as $folder) {
            if (!in_array($folder, $folders, true)) {
                $folders[] = $folder;
            }
        }

        $found = [];
        foreach ($folders as $folder) {
            $index = $storage->search_once($folder, $criteria);
            if (!is_object($index) || $index->is_error() || $index->is_empty()) {
                continue;
            }
            foreach ($index->get() as $uid) {
                $uid = (int) $uid;
                if ($uid <= 0) {
                    continue;
                }
                $found[] = ['uid' => $uid, 'folder' => $folder];
                if (count($found) >= 5) {
                    return $found;
                }
            }
            if ($found !== []) {
                return $found;
            }
        }

        return $found;
    }

    private function store_message_flag(int $uid, string $folder, string $flag): bool
    {
        if ($uid <= 0 || $folder === '') {
            return false;
        }

        $storage = $this->ctx->rcmail()->get_storage();
        $header = $storage->get_message_headers($uid, $folder);
        if (!$header) {
            return false;
        }
        if (!empty($header->flags[$flag])) {
            return true;
        }

        return (bool) $storage->set_flag((string) $uid, $flag, $folder);
    }

    /**
     * @param array<string, mixed> $result
     * @param array{uid: int, folder: string, set: bool}|null $answered
     * @return array<string, mixed>
     */
    private function attach_answered(array $result, ?array $answered): array
    {
        if ($answered === null) {
            return $result;
        }

        $result['answered'] = $answered['set'];
        if ($answered['set']) {
            $result['answered_uid'] = $answered['uid'];
            $result['answered_folder'] = $answered['folder'];
            return $result;
        }

        return $this->append_warning(
            $result,
            'The message was sent, but the original was not marked Answered, so mail clients will not show it as replied. Pass reply_uid and reply_folder from getMessage.'
        );
    }

    /**
     * @param array<string, mixed> $result
     * @return array<string, mixed>
     */
    private function append_warning(array $result, string $warning): array
    {
        if ($warning === '') {
            return $result;
        }
        if (!empty($result['warning'])) {
            $result['warning'] = rtrim((string) $result['warning'], '.') . '. ' . $warning;
            return $result;
        }
        $result['warning'] = $warning;

        return $result;
    }

    /** @return array<string, mixed> */
    private function summarize_header(rcube_message_header $header, string $folder): array
    {
        return [
            'uid' => (int) $header->uid,
            'folder' => $folder,
            'subject' => (string) ($header->subject ?? '(no subject)'),
            'from' => (string) ($header->from ?? ''),
            'to' => (string) ($header->to ?? ''),
            'date' => isset($header->timestamp) ? gmdate('c', (int) $header->timestamp) : (string) ($header->date ?? ''),
            'size' => (int) ($header->size ?? 0),
            'seen' => (bool) ($header->flags['SEEN'] ?? false),
            'flagged' => (bool) ($header->flags['FLAGGED'] ?? false),
            'answered' => (bool) ($header->flags['ANSWERED'] ?? false),
        ];
    }
}

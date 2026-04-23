import { bind } from 'decko';
import type { IDisposable, ITerminalOptions } from '@xterm/xterm';
import { Terminal } from '@xterm/xterm';
import { CanvasAddon } from '@xterm/addon-canvas';
import { ClipboardAddon } from '@xterm/addon-clipboard';
import { WebglAddon } from '@xterm/addon-webgl';
import { FitAddon } from '@xterm/addon-fit';
import { WebLinksAddon } from '@xterm/addon-web-links';
import { ImageAddon } from '@xterm/addon-image';
import { Unicode11Addon } from '@xterm/addon-unicode11';
import { OverlayAddon } from './addons/overlay';
import { ZmodemAddon } from './addons/zmodem';

import '@xterm/xterm/css/xterm.css';

interface TtydTerminal extends Terminal {
    fit(): void;
}

declare global {
    interface Window {
        term: TtydTerminal;
    }
}

enum Command {
    // server side
    OUTPUT = '0',
    SET_WINDOW_TITLE = '1',
    SET_PREFERENCES = '2',

    // client side
    INPUT = '0',
    RESIZE_TERMINAL = '1',
    PAUSE = '2',
    RESUME = '3',
}
type Preferences = ITerminalOptions & ClientOptions;

export type RendererType = 'dom' | 'canvas' | 'webgl';

export interface ClientOptions {
    rendererType: RendererType;
    disableLeaveAlert: boolean;
    disableResizeOverlay: boolean;
    enableZmodem: boolean;
    enableTrzsz: boolean;
    enableSixel: boolean;
    titleFixed?: string;
    isWindows: boolean;
    trzszDragInitTimeout: number;
    unicodeVersion: string;
    closeOnDisconnect: boolean;
}

export interface FlowControl {
    limit: number;
    highWater: number;
    lowWater: number;
}

export interface Endpoints {
    session: string;
    poll: string;
    input: string;
    close: string;
}

export interface XtermOptions {
    endpoints: Endpoints;
    tokenUrl: string;
    flowControl: FlowControl;
    clientOptions: ClientOptions;
    termOptions: ITerminalOptions;
}

function toDisposable(f: () => void): IDisposable {
    return { dispose: f };
}

function addEventListener(target: EventTarget, type: string, listener: EventListener): IDisposable {
    target.addEventListener(type, listener);
    return toDisposable(() => target.removeEventListener(type, listener));
}

export class Xterm {
    private disposables: IDisposable[] = [];
    private textEncoder = new TextEncoder();
    private textDecoder = new TextDecoder();
    private written = 0;
    private pending = 0;

    private terminal: Terminal;
    private fitAddon = new FitAddon();
    private overlayAddon = new OverlayAddon();
    private clipboardAddon = new ClipboardAddon();
    private webLinksAddon = new WebLinksAddon();
    private webglAddon?: WebglAddon;
    private canvasAddon?: CanvasAddon;
    private zmodemAddon?: ZmodemAddon;

    private sid?: string;
    private connected = false;
    private pollAbort?: AbortController;
    private inputQueue: Uint8Array[] = [];
    private inputInFlight = false;
    private token: string;
    private opened = false;
    private title?: string;
    private titleFixed?: string;
    private resizeOverlay = true;
    private reconnect = true;
    private doReconnect = true;
    private closeOnDisconnect = false;
    private listenersAttached = false;

    private writeFunc = (data: ArrayBuffer) => this.writeData(new Uint8Array(data));

    constructor(
        private options: XtermOptions,
        private sendCb: () => void
    ) {}

    dispose() {
        for (const d of this.disposables) {
            d.dispose();
        }
        this.disposables.length = 0;
        this.listenersAttached = false;
    }

    @bind
    private register<T extends IDisposable>(d: T): T {
        this.disposables.push(d);
        return d;
    }

    @bind
    public sendFile(files: FileList) {
        this.zmodemAddon?.sendFile(files);
    }

    @bind
    public async refreshToken() {
        try {
            const resp = await fetch(this.options.tokenUrl);
            if (resp.ok) {
                const json = await resp.json();
                this.token = json.token;
            }
        } catch (e) {
            console.error(`[ttyd] fetch ${this.options.tokenUrl}: `, e);
        }
    }

    @bind
    private onWindowUnload(event: BeforeUnloadEvent) {
        event.preventDefault();
        if (this.connected) {
            const message = 'Close terminal? this will also terminate the command.';
            event.returnValue = message;
            // Best-effort session close using sendBeacon so the pty is reaped
            // immediately instead of waiting for the idle timer.
            if (this.sid) {
                try {
                    navigator.sendBeacon(this.closeUrl(this.sid));
                } catch {
                    // ignore
                }
            }
            return message;
        }
        return undefined;
    }

    private closeUrl(sid: string): string {
        return `${this.options.endpoints.close}?sid=${encodeURIComponent(sid)}`;
    }

    @bind
    public open(parent: HTMLElement) {
        this.terminal = new Terminal(this.options.termOptions);
        const { terminal, fitAddon, overlayAddon, clipboardAddon, webLinksAddon } = this;
        window.term = terminal as TtydTerminal;
        window.term.fit = () => {
            this.fitAddon.fit();
        };

        terminal.loadAddon(fitAddon);
        terminal.loadAddon(overlayAddon);
        terminal.loadAddon(clipboardAddon);
        terminal.loadAddon(webLinksAddon);

        terminal.open(parent);
        fitAddon.fit();
    }

    @bind
    private initListeners() {
        if (this.listenersAttached) return;
        this.listenersAttached = true;

        const { terminal, fitAddon, overlayAddon, register, sendData, sendBinary } = this;
        register(
            terminal.onTitleChange(data => {
                if (data && data !== '' && !this.titleFixed) {
                    document.title = data + ' | ' + this.title;
                }
            })
        );
        register(terminal.onData(data => sendData(data)));
        register(terminal.onBinary(data => sendData(Uint8Array.from(data, v => v.charCodeAt(0)))));
        register(
            terminal.onResize(({ cols, rows }) => {
                const msg = JSON.stringify({ columns: cols, rows: rows });
                const payload = new Uint8Array(msg.length + 1);
                payload[0] = Command.RESIZE_TERMINAL.charCodeAt(0);
                this.textEncoder.encodeInto(msg, payload.subarray(1));
                sendBinary(payload);
                if (this.resizeOverlay) overlayAddon.showOverlay(`${cols}x${rows}`, 300);
            })
        );
        register(
            terminal.onSelectionChange(() => {
                if (this.terminal.getSelection() === '') return;
                try {
                    document.execCommand('copy');
                } catch (e) {
                    return;
                }
                this.overlayAddon?.showOverlay('✂', 200);
            })
        );
        register(addEventListener(window, 'resize', () => fitAddon.fit()));
        register(addEventListener(window, 'beforeunload', this.onWindowUnload));
    }

    @bind
    public writeData(data: string | Uint8Array) {
        const { terminal } = this;
        const { limit, highWater, lowWater } = this.options.flowControl;

        this.written += data.length;
        if (this.written > limit) {
            terminal.write(data, () => {
                this.pending = Math.max(this.pending - 1, 0);
                if (this.pending < lowWater) {
                    this.sendBinary(this.textEncoder.encode(Command.RESUME));
                }
            });
            this.pending++;
            this.written = 0;
            if (this.pending > highWater) {
                this.sendBinary(this.textEncoder.encode(Command.PAUSE));
            }
        } else {
            terminal.write(data);
        }
    }

    @bind
    public sendData(data: string | Uint8Array) {
        if (!this.connected) return;

        if (typeof data === 'string') {
            const payload = new Uint8Array(data.length * 3 + 1);
            payload[0] = Command.INPUT.charCodeAt(0);
            const stats = this.textEncoder.encodeInto(data, payload.subarray(1));
            this.sendBinary(payload.subarray(0, (stats.written as number) + 1));
        } else {
            const payload = new Uint8Array(data.length + 1);
            payload[0] = Command.INPUT.charCodeAt(0);
            payload.set(data, 1);
            this.sendBinary(payload);
        }
    }

    @bind
    private sendBinary(payload: Uint8Array) {
        if (!this.sid) return;
        // Queue so the server sees frames in the order the terminal produced
        // them — trzsz / zmodem break under reordering, and concurrent fetches
        // offer no ordering guarantees.
        this.inputQueue.push(payload);
        if (!this.inputInFlight) void this.drainInput();
    }

    @bind
    private async drainInput() {
        if (this.inputInFlight || !this.sid) return;
        this.inputInFlight = true;
        try {
            const INPUT_BYTE = Command.INPUT.charCodeAt(0);
            while (this.inputQueue.length > 0 && this.sid) {
                // Coalesce runs of INPUT frames into a single POST body.
                // Non-INPUT frames (resize/pause/resume) each go in their own
                // POST so their leading command byte isn't swallowed.
                const first = this.inputQueue[0];
                let body: Uint8Array;
                if (first[0] === INPUT_BYTE) {
                    const parts: Uint8Array[] = [];
                    let total = 0;
                    while (this.inputQueue.length > 0 && this.inputQueue[0][0] === INPUT_BYTE) {
                        const chunk = this.inputQueue.shift()!;
                        const slice = parts.length === 0 ? chunk : chunk.subarray(1);
                        parts.push(slice);
                        total += slice.length;
                    }
                    body = new Uint8Array(total);
                    let off = 0;
                    for (const p of parts) {
                        body.set(p, off);
                        off += p.length;
                    }
                } else {
                    body = this.inputQueue.shift()!;
                }
                try {
                    await fetch(`${this.options.endpoints.input}?sid=${encodeURIComponent(this.sid)}`, {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/octet-stream' },
                        body,
                    });
                } catch (err) {
                    console.warn('[ttyd] input POST failed:', err);
                    // Drop remaining queue; poll loop will surface the disconnect.
                    this.inputQueue.length = 0;
                    return;
                }
            }
        } finally {
            this.inputInFlight = false;
        }
    }

    @bind
    public async connect() {
        const { terminal } = this;
        const msg = JSON.stringify({ AuthToken: this.token, columns: terminal.cols, rows: terminal.rows });

        try {
            const resp = await fetch(this.options.endpoints.session + window.location.search, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: msg,
            });
            if (!resp.ok) {
                console.error(`[ttyd] session create failed: ${resp.status}`);
                this.handleDisconnect(resp.status === 401 ? 1000 : 1006);
                return;
            }
            const json = await resp.json();
            this.sid = json.sid;
        } catch (e) {
            console.error('[ttyd] session create error:', e);
            this.handleDisconnect(1006);
            return;
        }

        console.log(`[ttyd] session opened: ${this.sid}`);
        this.connected = true;
        this.doReconnect = this.reconnect;

        if (this.opened) {
            terminal.reset();
            terminal.options.disableStdin = false;
            this.overlayAddon.showOverlay('Reconnected', 300);
        } else {
            this.opened = true;
        }

        this.initListeners();
        terminal.focus();
        this.pollLoop();
    }

    @bind
    private async pollLoop() {
        while (this.connected && this.sid) {
            this.pollAbort = new AbortController();
            let resp: Response;
            try {
                resp = await fetch(`${this.options.endpoints.poll}?sid=${encodeURIComponent(this.sid)}`, {
                    method: 'GET',
                    signal: this.pollAbort.signal,
                });
            } catch (e) {
                if ((e as DOMException).name === 'AbortError') return;
                console.warn('[ttyd] poll error:', e);
                // network hiccup — brief backoff then try again
                await new Promise(r => setTimeout(r, 1000));
                continue;
            }

            if (resp.status === 204) {
                // server held then timed out with no data; loop immediately
                continue;
            }
            if (resp.status === 410 || resp.status === 404) {
                const code = resp.status === 410 ? 1000 : 1006;
                this.handleDisconnect(code);
                return;
            }
            if (!resp.ok) {
                console.error(`[ttyd] poll HTTP ${resp.status}`);
                this.handleDisconnect(1006);
                return;
            }

            const buf = await resp.arrayBuffer();
            this.dispatchBatch(buf);
        }
    }

    @bind
    private dispatchBatch(buf: ArrayBuffer) {
        const view = new DataView(buf);
        let off = 0;
        while (off + 4 <= buf.byteLength) {
            const msgLen = view.getUint32(off, false);
            off += 4;
            if (off + msgLen > buf.byteLength) {
                console.warn('[ttyd] truncated message in poll body');
                return;
            }
            const cmd = String.fromCharCode(view.getUint8(off));
            const payload = buf.slice(off + 1, off + msgLen);
            off += msgLen;
            this.handleMessage(cmd, payload);
        }
    }

    @bind
    private handleMessage(cmd: string, data: ArrayBuffer) {
        switch (cmd) {
            case Command.OUTPUT:
                this.writeFunc(data);
                break;
            case Command.SET_WINDOW_TITLE:
                this.title = this.textDecoder.decode(data);
                document.title = this.title;
                break;
            case Command.SET_PREFERENCES:
                this.applyPreferences({
                    ...this.options.clientOptions,
                    ...JSON.parse(this.textDecoder.decode(data)),
                    ...this.parseOptsFromUrlQuery(window.location.search),
                } as Preferences);
                break;
            default:
                console.warn(`[ttyd] unknown command: ${cmd}`);
                break;
        }
    }

    @bind
    private handleDisconnect(code: number) {
        console.log(`[ttyd] session disconnected with code: ${code}`);
        const wasConnected = this.connected;
        this.connected = false;
        this.sid = undefined;
        this.pollAbort?.abort();
        this.pollAbort = undefined;
        this.inputQueue.length = 0;

        if (!wasConnected && !this.opened) {
            // never connected in the first place — surface a minimal overlay
            this.overlayAddon.showOverlay('Connection Closed');
            return;
        }

        const { refreshToken, connect, doReconnect, overlayAddon, terminal } = this;
        overlayAddon.showOverlay('Connection Closed');
        this.dispose();

        if (code !== 1000 && doReconnect) {
            overlayAddon.showOverlay('Reconnecting...');
            refreshToken().then(connect);
        } else if (this.closeOnDisconnect) {
            window.close();
        } else {
            const keyDispose = terminal.onKey(e => {
                const event = e.domEvent;
                if (event.key === 'Enter') {
                    keyDispose.dispose();
                    overlayAddon.showOverlay('Reconnecting...');
                    refreshToken().then(connect);
                }
            });
            overlayAddon.showOverlay('Press ⏎ to Reconnect');
        }
    }

    @bind
    private parseOptsFromUrlQuery(query: string): Preferences {
        const { terminal } = this;
        const { clientOptions } = this.options;
        const prefs = {} as Preferences;
        const queryObj = Array.from(new URLSearchParams(query) as unknown as Iterable<[string, string]>);

        for (const [k, queryVal] of queryObj) {
            let v = clientOptions[k];
            if (v === undefined) v = terminal.options[k];
            switch (typeof v) {
                case 'boolean':
                    prefs[k] = queryVal === 'true' || queryVal === '1';
                    break;
                case 'number':
                case 'bigint':
                    prefs[k] = Number.parseInt(queryVal, 10);
                    break;
                case 'string':
                    prefs[k] = queryVal;
                    break;
                case 'object':
                    prefs[k] = JSON.parse(queryVal);
                    break;
                default:
                    console.warn(`[ttyd] maybe unknown option: ${k}=${queryVal}, treating as string`);
                    prefs[k] = queryVal;
                    break;
            }
        }

        return prefs;
    }

    @bind
    private applyPreferences(prefs: Preferences) {
        const { terminal, fitAddon, register } = this;
        if (prefs.enableZmodem || prefs.enableTrzsz) {
            this.zmodemAddon = new ZmodemAddon({
                zmodem: prefs.enableZmodem,
                trzsz: prefs.enableTrzsz,
                windows: prefs.isWindows,
                trzszDragInitTimeout: prefs.trzszDragInitTimeout,
                onSend: this.sendCb,
                sender: this.sendData,
                writer: this.writeData,
            });
            this.writeFunc = data => this.zmodemAddon?.consume(data);
            terminal.loadAddon(register(this.zmodemAddon));
        }

        for (const [key, value] of Object.entries(prefs)) {
            switch (key) {
                case 'rendererType':
                    this.setRendererType(value);
                    break;
                case 'disableLeaveAlert':
                    if (value) {
                        window.removeEventListener('beforeunload', this.onWindowUnload);
                        console.log('[ttyd] Leave site alert disabled');
                    }
                    break;
                case 'disableResizeOverlay':
                    if (value) {
                        console.log('[ttyd] Resize overlay disabled');
                        this.resizeOverlay = false;
                    }
                    break;
                case 'disableReconnect':
                    if (value) {
                        console.log('[ttyd] Reconnect disabled');
                        this.reconnect = false;
                        this.doReconnect = false;
                    }
                    break;
                case 'enableZmodem':
                    if (value) console.log('[ttyd] Zmodem enabled');
                    break;
                case 'enableTrzsz':
                    if (value) console.log('[ttyd] trzsz enabled');
                    break;
                case 'trzszDragInitTimeout':
                    if (value) console.log(`[ttyd] trzsz drag init timeout: ${value}`);
                    break;
                case 'enableSixel':
                    if (value) {
                        terminal.loadAddon(register(new ImageAddon()));
                        console.log('[ttyd] Sixel enabled');
                    }
                    break;
                case 'closeOnDisconnect':
                    if (value) {
                        console.log('[ttyd] close on disconnect enabled (Reconnect disabled)');
                        this.closeOnDisconnect = true;
                        this.reconnect = false;
                        this.doReconnect = false;
                    }
                    break;
                case 'titleFixed':
                    if (!value || value === '') return;
                    console.log(`[ttyd] setting fixed title: ${value}`);
                    this.titleFixed = value;
                    document.title = value;
                    break;
                case 'isWindows':
                    if (value) console.log('[ttyd] is windows');
                    break;
                case 'unicodeVersion':
                    switch (value) {
                        case 6:
                        case '6':
                            console.log('[ttyd] setting Unicode version: 6');
                            break;
                        case 11:
                        case '11':
                        default:
                            console.log('[ttyd] setting Unicode version: 11');
                            terminal.loadAddon(new Unicode11Addon());
                            terminal.unicode.activeVersion = '11';
                            break;
                    }
                    break;
                default:
                    console.log(`[ttyd] option: ${key}=${JSON.stringify(value)}`);
                    if (terminal.options[key] instanceof Object) {
                        terminal.options[key] = Object.assign({}, terminal.options[key], value);
                    } else {
                        terminal.options[key] = value;
                    }
                    if (key.indexOf('font') === 0) fitAddon.fit();
                    break;
            }
        }
    }

    @bind
    private setRendererType(value: RendererType) {
        const { terminal } = this;
        const disposeCanvasRenderer = () => {
            try {
                this.canvasAddon?.dispose();
            } catch {
                // ignore
            }
            this.canvasAddon = undefined;
        };
        const disposeWebglRenderer = () => {
            try {
                this.webglAddon?.dispose();
            } catch {
                // ignore
            }
            this.webglAddon = undefined;
        };
        const enableCanvasRenderer = () => {
            if (this.canvasAddon) return;
            this.canvasAddon = new CanvasAddon();
            disposeWebglRenderer();
            try {
                this.terminal.loadAddon(this.canvasAddon);
                console.log('[ttyd] canvas renderer loaded');
            } catch (e) {
                console.log('[ttyd] canvas renderer could not be loaded, falling back to dom renderer', e);
                disposeCanvasRenderer();
            }
        };
        const enableWebglRenderer = () => {
            if (this.webglAddon) return;
            this.webglAddon = new WebglAddon();
            disposeCanvasRenderer();
            try {
                this.webglAddon.onContextLoss(() => {
                    this.webglAddon?.dispose();
                });
                terminal.loadAddon(this.webglAddon);
                console.log('[ttyd] WebGL renderer loaded');
            } catch (e) {
                console.log('[ttyd] WebGL renderer could not be loaded, falling back to canvas renderer', e);
                disposeWebglRenderer();
                enableCanvasRenderer();
            }
        };

        switch (value) {
            case 'canvas':
                enableCanvasRenderer();
                break;
            case 'webgl':
                enableWebglRenderer();
                break;
            case 'dom':
                disposeWebglRenderer();
                disposeCanvasRenderer();
                console.log('[ttyd] dom renderer loaded');
                break;
            default:
                break;
        }
    }
}

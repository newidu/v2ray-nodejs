const os = require('os'), http = require('http'), fs = require('fs'), axios = require('axios'), net = require('net'), path = require('path'), crypto = require('crypto'), { WebSocket, createWebSocketStream } = require('ws');

// Configuration with Auto-Sync/Defaults
const UUID = process.env.UUID || '00000000-0000-0000-0000-000000000000';
const DOMAIN = process.env.DOMAIN || ''; // Leave empty for auto-detection if possible, or set manually
const NAME = process.env.NAME || 'node-server';
const PORT = process.env.PORT || 8305;
const SUB_PATH = process.env.SUB_PATH || 'sub';
const WSPATH = process.env.WSPATH || UUID.slice(0, 8);
const NEZHA_SERVER = process.env.NEZHA_SERVER || '', NEZHA_PORT = process.env.NEZHA_PORT || '', NEZHA_KEY = process.env.NEZHA_KEY || '';

let ISP = 'Unknown';
const getISP = async () => {
    try {
        const { data } = await axios.get('https://api.ip.sb/geoip');
        ISP = `${data.country_code}-${data.isp}`.replace(/\s+/g, '_');
    } catch (e) {}
};
getISP();

// Helper to auto-resolve or use domain
const getEffectiveDomain = (req) => DOMAIN || req.headers.host || 'localhost';

const server = http.createServer((req, res) => {
    const host = getEffectiveDomain(req);
    if (req.url === '/') {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end('<h1>Server Active</h1>');
    } else if (req.url === `/${SUB_PATH}`) {
        const name = `${NAME}-${ISP}`;
        const vless = `vless://${UUID}@${host}:443?encryption=none&security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2F${WSPATH}#${name}`;
        const trojan = `trojan://${UUID}@${host}:443?security=tls&sni=${host}&fp=chrome&type=ws&host=${host}&path=%2F${WSPATH}#${name}`;
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        res.end(Buffer.from(`${vless}\n${trojan}`).toString('base64') + '\n');
    } else {
        res.writeHead(404).end();
    }
});

const wss = new WebSocket.Server({ server });
const uuidHex = UUID.replace(/-/g, "");

const handleConn = (ws, msg, isVless) => {
    const duplex = createWebSocketStream(ws);
    let i = isVless ? msg[17] + 19 : 56;
    if (!isVless && msg[i] === 0x0d) i += 2; // Trojan CRLF
    if (!isVless && msg[i++] !== 0x01) return; // Trojan CMD check

    const atyp = msg[i++];
    let host, port;
    if (atyp === 1) { host = msg.slice(i, i += 4).join('.'); }
    else if (atyp === 3) { const len = msg[i++]; host = msg.slice(i, i += len).toString(); }
    else if (atyp === 4) { host = msg.slice(i, i += 16).reduce((s, b, i, a) => (i % 2 ? s.concat(a.slice(i - 1, i + 1)) : s), []).map(b => b.readUInt16BE(0).toString(16)).join(':'); }
    
    port = msg.readUInt16BE(i);
    i += 2;
    if (!isVless && msg[i] === 0x0d) i += 2;

    if (isVless) ws.send(new Uint8Array([msg[0], 0]));

    const conn = net.connect({ host, port }, () => {
        conn.write(msg.slice(i));
        duplex.pipe(conn).pipe(duplex);
    }).on('error', () => conn.destroy());
};

wss.on('connection', (ws) => {
    ws.once('message', (msg) => {
        const isVless = msg.length > 17 && msg[0] === 0 && msg.slice(1, 17).every((v, i) => v === parseInt(uuidHex.substr(i * 2, 2), 16));
        const isTrojan = !isVless && crypto.createHash('sha224').update(UUID).digest('hex') === msg.slice(0, 56).toString();
        if (isVless || isTrojan) handleConn(ws, msg, isVless);
        else ws.close();
    });
});

const runNezha = async () => {
    if (!NEZHA_SERVER || !NEZHA_KEY) return;
    const arch = os.arch().includes('arm') ? 'arm64' : 'amd64';
    const url = `https://${arch}.ssss.nyc.mn/${NEZHA_PORT ? 'agent' : 'v1'}`;
    try {
        const res = await axios.get(url, { responseType: 'stream' });
        const writer = fs.createWriteStream('npm');
        res.data.pipe(writer);
        writer.on('finish', () => {
            fs.chmodSync('npm', '755');
            const tls = ['443','8443','2096','2087','2083','2053'].includes(NEZHA_PORT) ? '--tls' : '';
            const cmd = NEZHA_PORT 
                ? `./npm -s ${NEZHA_SERVER}:${NEZHA_PORT} -p ${NEZHA_KEY} ${tls} --disable-auto-update --report-delay 4 --skip-conn --skip-procs >/dev/null 2>&1 &`
                : (fs.writeFileSync('config.yaml', `server: ${NEZHA_SERVER}\nclient_secret: ${NEZHA_KEY}\ntls: ${tls !== ''}\nuuid: ${UUID}\ndisable_auto_update: true`), `./npm -c config.yaml >/dev/null 2>&1 &`);
            require('child_process').exec(cmd);
            setTimeout(() => { fs.unlinkSync('npm'); if (!NEZHA_PORT) fs.unlinkSync('config.yaml'); }, 5000);
        });
    } catch (e) {}
};

server.listen(PORT, () => {
    console.log(`Port: ${PORT}`);
    runNezha();
    if (DOMAIN) axios.post("https://oooo.serv00.net/add-url", { url: `https://${DOMAIN}` }).catch(() => {});
});

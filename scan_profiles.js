/**
 * Scan VSCode .code-profile files for potentially sensitive data.
 * Usage: node scan_profiles.js [diretório]
 * Se o diretório não for informado, usa o diretório atual do script.
 */

const fs = require('fs');
const path = require('path');

// ─── Padrões benignos em globalState que geram falsos positivos ──────────────
// O globalState contém estado de UI com UUIDs em chaves como *.hidden, *.state etc.
// Esses padrões de chave são excluídos da verificação de hex/base64.

const GLOBALSTATE_BENIGN_KEY_PATTERNS = [
  /\.hidden$/,
  /\.state$/,
  /\.visible$/,
  /\.collapsed$/,
  /\.expanded$/,
  /workbench\./,
  /\.views\./,
  /\.panel\./,
  /scm\./,
  /terminal\./,
  /editor\./,
  /\.pinned$/,
  /\.order$/,
];

// Padrões que só fazem sentido em settings, não em globalState UI
const GLOBALSTATE_SKIP_PATTERNS = ['Hash/Token hexadecimal longo', 'String Base64 longa (possível token)'];

// ─── Padrões suspeitos em VALORES de settings ────────────────────────────────

const VALUE_PATTERNS = [
  // Tokens GitHub
  { name: 'GitHub PAT (ghp_)',         regex: /ghp_[A-Za-z0-9]{36,}/ },
  { name: 'GitHub OAuth (gho_)',        regex: /gho_[A-Za-z0-9]{36,}/ },
  { name: 'GitHub Server (ghs_)',       regex: /ghs_[A-Za-z0-9]{36,}/ },
  { name: 'GitHub Refresh (ghr_)',      regex: /ghr_[A-Za-z0-9]{36,}/ },
  // AWS
  { name: 'AWS Access Key ID',          regex: /AKIA[A-Z0-9]{16}/ },
  { name: 'AWS Secret (possível)',       regex: /aws[_\-.]?secret/i },
  // Slack
  { name: 'Slack Token',                regex: /xox[baprs]-[0-9A-Za-z\-]{10,}/ },
  // JWT
  { name: 'JWT Token',                  regex: /eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+/ },
  // Senhas em URLs (jdbc, mongo, postgres, etc.)
  { name: 'Credencial em URL',          regex: /\w+:\/\/[^@\s]+:[^@\s]+@/ },
  // Connection strings comuns
  { name: 'Connection String MongoDB',  regex: /mongodb(\+srv)?:\/\//i },
  { name: 'Connection String Postgres', regex: /postgres(ql)?:\/\//i },
  { name: 'Connection String MySQL',    regex: /mysql:\/\//i },
  { name: 'Connection String Redis',    regex: /redis:\/\//i },
  // Chaves privadas
  { name: 'Chave Privada (PEM)',         regex: /-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----/ },
  // Hex 32+ chars (MD5/SHA hash ou token)
  { name: 'Hash/Token hexadecimal longo', regex: /\b[0-9a-f]{32,}\b/i },
  // Base64 que parece token (40+ chars sem espaços)
  { name: 'String Base64 longa (possível token)', regex: /[A-Za-z0-9+\/]{40,}={0,2}/ },
];

// ─── Nomes de chaves de settings que sempre merecem atenção ─────────────────

const SENSITIVE_KEY_PATTERNS = [
  /token/i,
  /secret/i,
  /password/i,
  /passwd/i,
  /apikey/i,
  /api[_\-.]?key/i,
  /access[_\-.]?key/i,
  /private[_\-.]?key/i,
  /credential/i,
  /auth[_\-.]?token/i,
  /bearer/i,
  /gist/i,          // sync.gist pode conter ID de Gist público/privado
  /passphrase/i,
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function tryParse(val) {
  if (typeof val !== 'string') return val;
  try { return JSON.parse(val); } catch { return val; }
}

function maskValue(val) {
  const s = String(val);
  if (s.length <= 6) return '***';
  return s.slice(0, 3) + '*'.repeat(Math.min(s.length - 6, 20)) + s.slice(-3);
}

function scanObject(obj, prefix, findings) {
  if (!obj || typeof obj !== 'object') return;
  for (const [key, value] of Object.entries(obj)) {
    const fullKey = prefix ? `${prefix}.${key}` : key;
    const strValue = typeof value === 'string' ? value : JSON.stringify(value);

    // Chave suspeita
    const suspiciousKey = SENSITIVE_KEY_PATTERNS.some(p => p.test(key));
    if (suspiciousKey && strValue.trim().length > 0) {
      findings.push({
        severity: 'ATENÇÃO',
        reason: `Chave com nome suspeito: "${key}"`,
        key: fullKey,
        value: maskValue(strValue),
        rawValue: strValue,
      });
    }

    // Valor suspeito
    for (const { name, regex } of VALUE_PATTERNS) {
      if (regex.test(strValue)) {
        // Evitar duplicar se já foi registrado pela chave suspeita
        const alreadyLogged = findings.some(f => f.key === fullKey && f.reason.includes(name));
        if (!alreadyLogged) {
          findings.push({
            severity: 'ALERTA',
            reason: `Padrão detectado no valor: ${name}`,
            key: fullKey,
            value: maskValue(strValue),
            rawValue: strValue,
          });
        }
      }
    }

    // Recursão em sub-objetos
    if (value && typeof value === 'object' && !Array.isArray(value)) {
      scanObject(value, fullKey, findings);
    }
  }
}

function scanProfile(filePath) {
  const findings = [];
  const raw = fs.readFileSync(filePath, 'utf8');
  const profile = JSON.parse(raw);

  // ── Settings ──────────────────────────────────────────────────────────────
  if (profile.settings) {
    const outer = tryParse(profile.settings);
    const inner = tryParse(outer?.settings ?? outer);
    if (inner && typeof inner === 'object') {
      scanObject(inner, 'settings', findings);
    }
  }

  // ── Keybindings ───────────────────────────────────────────────────────────
  if (profile.keybindings) {
    const kb = tryParse(profile.keybindings);
    const bindings = tryParse(kb?.keybindings ?? kb);
    if (Array.isArray(bindings)) {
      bindings.forEach((b, i) => scanObject(b, `keybindings[${i}]`, findings));
    }
  }

  // ── Snippets ──────────────────────────────────────────────────────────────
  if (profile.snippets) {
    const sn = tryParse(profile.snippets);
    const list = tryParse(sn?.snippets ?? sn);
    if (Array.isArray(list)) {
      list.forEach((s, i) => {
        const content = tryParse(s?.content ?? s);
        if (content && typeof content === 'object') {
          scanObject(content, `snippets[${i}]`, findings);
        }
      });
    }
  }

  // ── GlobalState ───────────────────────────────────────────────────────────
  if (profile.globalState) {
    const gs = tryParse(profile.globalState);
    if (gs?.storage) {
      for (const [stateKey, stateVal] of Object.entries(gs.storage)) {
        const isBenignKey = GLOBALSTATE_BENIGN_KEY_PATTERNS.some(p => p.test(stateKey));
        const strVal = typeof stateVal === 'string' ? stateVal : JSON.stringify(stateVal);
        for (const { name, regex } of VALUE_PATTERNS) {
          // Pular padrões de hex/base64 em chaves de UI conhecidas (falsos positivos)
          if (isBenignKey && GLOBALSTATE_SKIP_PATTERNS.includes(name)) continue;
          if (regex.test(strVal)) {
            findings.push({
              severity: 'ALERTA',
              reason: `Padrão detectado em globalState: ${name}`,
              key: `globalState.storage.${stateKey}`,
              value: maskValue(strVal),
              rawValue: strVal,
            });
          }
        }
      }
    }
  }

  return findings;
}

// ─── Main ────────────────────────────────────────────────────────────────────

const targetDir = process.argv[2] || __dirname;
const profiles = fs.readdirSync(targetDir).filter(f => f.endsWith('.code-profile'));

if (profiles.length === 0) {
  console.log('Nenhum arquivo .code-profile encontrado em:', targetDir);
  process.exit(0);
}

let totalAlerts = 0;
let totalAttentions = 0;
const RESET = '\x1b[0m', RED = '\x1b[31m', YELLOW = '\x1b[33m', GREEN = '\x1b[32m', BOLD = '\x1b[1m', CYAN = '\x1b[36m';

console.log(`\n${BOLD}═══════════════════════════════════════════════════════${RESET}`);
console.log(`${BOLD}   Varredura de perfis VSCode — dados sensíveis${RESET}`);
console.log(`${BOLD}═══════════════════════════════════════════════════════${RESET}`);
console.log(`Diretório: ${targetDir}`);
console.log(`Perfis encontrados: ${profiles.length}\n`);

for (const profileFile of profiles) {
  const filePath = path.join(targetDir, profileFile);
  let findings;
  try {
    findings = scanProfile(filePath);
  } catch (err) {
    console.log(`${RED}[ERRO]${RESET} ${profileFile}: ${err.message}`);
    continue;
  }

  const alerts     = findings.filter(f => f.severity === 'ALERTA');
  const attentions = findings.filter(f => f.severity === 'ATENÇÃO');
  totalAlerts     += alerts.length;
  totalAttentions += attentions.length;

  const icon = alerts.length > 0 ? `${RED}✖${RESET}` : attentions.length > 0 ? `${YELLOW}⚠${RESET}` : `${GREEN}✔${RESET}`;
  console.log(`${BOLD}${icon}  ${profileFile}${RESET}`);

  if (findings.length === 0) {
    console.log(`   ${GREEN}Nenhum dado sensível detectado.${RESET}`);
  } else {
    for (const f of findings) {
      const color = f.severity === 'ALERTA' ? RED : YELLOW;
      console.log(`   ${color}[${f.severity}]${RESET} ${f.reason}`);
      console.log(`           Chave : ${CYAN}${f.key}${RESET}`);
      console.log(`           Valor : ${f.value}`);
    }
  }
  console.log();
}

console.log(`${BOLD}═══════════════════════════════════════════════════════${RESET}`);
console.log(`Resumo: ${RED}${totalAlerts} ALERTA(S)${RESET} | ${YELLOW}${totalAttentions} ATENÇÃO(ÕES)${RESET}`);
if (totalAlerts === 0 && totalAttentions === 0) {
  console.log(`${GREEN}Nenhum dado sensível encontrado nos perfis.${RESET}`);
} else {
  console.log(`\n${BOLD}Legendas:${RESET}`);
  console.log(`  ${RED}[ALERTA]${RESET}  — padrão que provavelmente é um segredo real (token, senha, chave)`);
  console.log(`  ${YELLOW}[ATENÇÃO]${RESET} — chave com nome suspeito; verifique manualmente o valor completo`);
  console.log(`\n${BOLD}Dica:${RESET} Para ver os valores completos (sem máscara), edite o script e`);
  console.log(`       substitua "maskValue(strValue)" por "strValue" nas chamadas findings.push.`);
}
console.log();

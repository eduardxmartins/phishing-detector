// ── HISTORY ──
function getHistory() {
  return JSON.parse(localStorage.getItem('phishing_history') || '[]');
}

function saveToHistory(entry) {
  const h = getHistory();
  h.unshift({ ...entry, id: Date.now(), date: new Date().toISOString() });
  localStorage.setItem('phishing_history', JSON.stringify(h.slice(0, 50)));
}

function getStats() {
  const h = getHistory();
  return {
    total: h.length,
    danger: h.filter(x => x.verdict === 'danger').length,
    safe: h.filter(x => x.verdict === 'safe').length,
  };
}

function setActiveNav() {
  const path = window.location.pathname.split('/').pop();
  document.querySelectorAll('.nav-link').forEach(a => {
    a.classList.remove('active');
    if (a.getAttribute('href') === path) a.classList.add('active');
  });
}

function renderResult(container, findings, d) {
  const icons  = { safe: '✓', suspicious: '!', danger: '✕' };
  const labels = { safe: 'Parece seguro', suspicious: 'Suspeito', danger: 'Alto risco de phishing' };
  const colors = { safe: '#639922', suspicious: '#EF9F27', danger: '#E24B4A' };

  const verdictBox = container.querySelector('.verdict-box');
  verdictBox.className = 'verdict ' + d.verdict;
  verdictBox.innerHTML = `
    <div class="verdict-icon">${icons[d.verdict]}</div>
    <div style="flex:1">
      <div class="verdict-label">${labels[d.verdict]}</div>
      <div class="verdict-summary">${d.summary}</div>
      <div class="score-row">
        <div class="score-bar-wrap">
          <div class="score-bar" style="width:${d.score}%;background:${colors[d.verdict]}"></div>
        </div>
        <span class="score-label">Risco: ${d.score}/100</span>
      </div>
    </div>`;

  const findingsEl = container.querySelector('.findings');
  findingsEl.innerHTML = findings.map(f => {
    const fc = f.level === 'red' ? 'var(--red-dark)' : f.level === 'amber' ? 'var(--amber-dark)' : 'var(--green-dark)';
    return `
      <div class="finding">
        <div class="finding-dot dot-${f.level}"></div>
        <div>
          <div class="finding-label" style="color:${fc}">${f.label}</div>
          <div class="finding-detail">${f.detail}</div>
        </div>
      </div>`;
  }).join('');
}

// ══════════════════════════════════════════
//  MOTOR DE DETECÇÃO LOCAL
// ══════════════════════════════════════════

const SUSPICIOUS_KEYWORDS = [
  'verificar conta','confirmar dados','acesso bloqueado','clique aqui urgente',
  'sua conta será encerrada','atualizar cadastro','dados bancários','senha expirou',
  'ganhou um prêmio','você foi selecionado','resgate agora','oferta exclusiva',
  'verify your account','click here immediately','your account will be closed',
  'update your information','confirm your password','you have been selected',
  'limited time offer','act now','suspended account'
];

const URGENT_WORDS = [
  'urgente','imediato','atenção','importante','alerta','aviso',
  'último aviso','prazo','expira','bloqueado','suspenso',
  'urgent','immediate','alert','warning','expires','blocked','suspended'
];

const TRUSTED_DOMAINS = [
  'google.com','microsoft.com','apple.com','amazon.com','facebook.com',
  'instagram.com','bradesco.com.br','itau.com.br','bb.com.br','caixa.gov.br',
  'santander.com.br','nubank.com.br','mercadolivre.com.br','gov.br',
  'receita.fazenda.gov.br','correios.com.br','netflix.com','spotify.com'
];

const SUSPICIOUS_TLDS = ['.xyz','.top','.click','.tk','.ml','.ga','.cf','.gq','.pw','.zip','.mov'];

function analyzeEmail(text) {
  const lower = text.toLowerCase();
  const findings = [];
  let score = 0;

  const urgentFound = URGENT_WORDS.filter(w => lower.includes(w));
  if (urgentFound.length >= 3) {
    score += 25;
    findings.push({ level: 'red', label: 'Linguagem de urgência extrema', detail: `Palavras de pressão encontradas: "${urgentFound.slice(0,4).join('", "')}". Phishing usa urgência para forçar cliques sem reflexão.` });
  } else if (urgentFound.length >= 1) {
    score += 10;
    findings.push({ level: 'amber', label: 'Linguagem de urgência', detail: `Palavras como "${urgentFound.slice(0,2).join('", "')}" foram detectadas. Pode ser legítimo, mas fique atento.` });
  }

  const phishFound = SUSPICIOUS_KEYWORDS.filter(w => lower.includes(w));
  if (phishFound.length >= 2) {
    score += 35;
    findings.push({ level: 'red', label: 'Padrões clássicos de phishing', detail: `Frases suspeitas: "${phishFound.slice(0,2).join('", "')}". Esses padrões são muito comuns em golpes.` });
  } else if (phishFound.length === 1) {
    score += 15;
    findings.push({ level: 'amber', label: 'Frase suspeita detectada', detail: `A frase "${phishFound[0]}" é frequentemente usada em e-mails de phishing.` });
  }

  const urlMatches = text.match(/https?:\/\/[^\s]+/gi) || [];
  if (urlMatches.length > 0) {
    const suspiciousLinks = urlMatches.filter(url => {
      const u = url.toLowerCase();
      return SUSPICIOUS_TLDS.some(tld => u.includes(tld)) ||
             u.includes('bit.ly') || u.includes('tinyurl') || u.includes('goo.gl') ||
             u.includes('redirect') || u.includes('token=') || u.includes('login?');
    });
    if (suspiciousLinks.length > 0) {
      score += 30;
      findings.push({ level: 'red', label: 'Links suspeitos no corpo', detail: `Link suspeito: ${suspiciousLinks[0].slice(0, 60)}. Encurtadores ou domínios incomuns são sinal de alerta.` });
    } else {
      findings.push({ level: 'amber', label: 'Links presentes no e-mail', detail: `${urlMatches.length} link(s) detectado(s). Verifique se os domínios são legítimos antes de clicar.` });
      score += 5;
    }
  }

  const sensitiveWords = ['cpf','senha','password','cartão','card','cvv','pin','conta corrente','agência'];
  const sensitiveFound = sensitiveWords.filter(w => lower.includes(w));
  if (sensitiveFound.length >= 2) {
    score += 30;
    findings.push({ level: 'red', label: 'Solicitação de dados sensíveis', detail: `Pede informações como "${sensitiveFound.slice(0,3).join('", "')}". Empresas legítimas NUNCA pedem esses dados por e-mail.` });
  }

  const excessivePunctuation = (text.match(/!{2,}|\?{2,}/g) || []).length;
  if (excessivePunctuation >= 3) {
    score += 10;
    findings.push({ level: 'amber', label: 'Pontuação excessiva', detail: 'Uso excessivo de "!!!" ou "???" é comum em e-mails de phishing para criar sensação de alerta.' });
  }

  if (urlMatches.length === 0 && phishFound.length === 0 && urgentFound.length === 0) {
    score = Math.max(0, score - 10);
    findings.push({ level: 'green', label: 'Sem links ou padrões suspeitos', detail: 'Nenhum link ou frase de phishing detectada neste e-mail.' });
  }

  return { score: Math.min(score, 100), findings };
}

function analyzeURL(url) {
  const lower = url.toLowerCase();
  const findings = [];
  let score = 0;

  let domain = '';
  try {
    domain = new URL(url.startsWith('http') ? url : 'https://' + url).hostname;
  } catch(e) {
    domain = url.split('/')[0];
  }

  if (!url.startsWith('https://')) {
    score += 20;
    findings.push({ level: 'red', label: 'Sem HTTPS', detail: 'A URL não usa HTTPS. Sites legítimos que pedem dados sempre usam conexão segura.' });
  } else {
    findings.push({ level: 'green', label: 'Usa HTTPS', detail: 'A conexão é criptografada — bom sinal, mas não garante que o site é legítimo.' });
  }

  const suspTLD = SUSPICIOUS_TLDS.find(tld => domain.endsWith(tld));
  if (suspTLD) {
    score += 30;
    findings.push({ level: 'red', label: `TLD suspeito (${suspTLD})`, detail: `Domínios com "${suspTLD}" são frequentemente usados em phishing por serem baratos ou gratuitos.` });
  }

  const imitated = TRUSTED_DOMAINS.find(td => {
    const tdBase = td.replace('.com.br','').replace('.com','').replace('.gov.br','').replace('.br','');
    return domain.includes(tdBase) && !domain.endsWith(td);
  });
  if (imitated) {
    score += 40;
    findings.push({ level: 'red', label: 'Imitação de marca conhecida', detail: `O domínio "${domain}" imita "${imitated}" mas não é o site oficial. Técnica clássica de phishing.` });
  }

  const parts = domain.split('.');
  if (parts.length >= 4) {
    score += 20;
    findings.push({ level: 'red', label: 'Subdomínios excessivos', detail: `O domínio tem ${parts.length} partes ("${domain}"), o que é incomum e suspeito.` });
  }

  if (/^\d{1,3}(\.\d{1,3}){3}/.test(domain)) {
    score += 35;
    findings.push({ level: 'red', label: 'URL com endereço IP', detail: 'A URL usa um IP numérico no lugar de um domínio. Sites legítimos raramente fazem isso.' });
  }

  const shorteners = ['bit.ly','tinyurl.com','goo.gl','t.co','ow.ly','is.gd','buff.ly'];
  if (shorteners.some(s => domain.includes(s))) {
    score += 20;
    findings.push({ level: 'amber', label: 'URL encurtada', detail: 'URLs encurtadas escondem o destino real. Desconfie se chegou por mensagem não solicitada.' });
  }

  if (lower.includes('login') || lower.includes('senha') || lower.includes('password') || lower.includes('token=')) {
    score += 15;
    findings.push({ level: 'amber', label: 'Parâmetros sensíveis na URL', detail: 'A URL contém termos como "login", "senha" ou "token". Verifique se o domínio é realmente o site oficial.' });
  }

  if (domain.length > 40) {
    score += 15;
    findings.push({ level: 'amber', label: 'Domínio muito longo', detail: `O domínio tem ${domain.length} caracteres. Domínios legítimos costumam ser curtos e diretos.` });
  }

  if (score === 0) {
    findings.push({ level: 'green', label: 'Domínio sem alertas', detail: `"${domain}" não apresentou nenhum sinal claro de phishing.` });
  }

  return { score: Math.min(score, 100), findings };
}

function getVerdict(score) {
  if (score <= 30) return 'safe';
  if (score <= 69) return 'suspicious';
  return 'danger';
}

function getSummary(verdict, score) {
  if (verdict === 'safe') return `Pontuação baixa (${score}/100). Nenhum indicador crítico encontrado.`;
  if (verdict === 'suspicious') return `Pontuação moderada (${score}/100). Alguns pontos merecem atenção.`;
  return `Pontuação alta (${score}/100). Múltiplos indicadores de phishing detectados.`;
}

window.addEventListener('DOMContentLoaded', setActiveNav);
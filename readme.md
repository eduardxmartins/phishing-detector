# 🛡️ Phishing Detector

![Phishing Detector](https://img.shields.io/badge/Cybersecurity-Phishing%20Detection-red)
![Version](https://img.shields.io/badge/version-1.0.0-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Offline](https://img.shields.io/badge/offline-100%25-brightgreen)

## 🔍 Sobre o Projeto

**Phishing Detector** é uma ferramenta profissional e **100% offline** para detecção de phishing em e-mails e URLs. Desenvolvida para estudantes e profissionais de cibersegurança, a ferramenta analisa padrões suspeitos e calcula um score de risco sem enviar dados para nenhum servidor externo.

## ✨ Funcionalidades

| Funcionalidade | Descrição |
|----------------|-----------|
| 📧 **Análise de E-mails** | Detecta linguagem urgente, pedidos de dados sensíveis e links suspeitos |
| 🔗 **Análise de URLs** | Verifica domínios, TLDs suspeitos, HTTPS e técnicas de phishing |
| 📊 **Score de Risco** | Pontuação de 0 a 100 (quanto maior, mais perigoso) |
| 📜 **Histórico Local** | Salva todas as análises no navegador (localStorage) |
| 🎨 **Interface Moderna** | Design profissional com tabs e cards |
| ⚡ **100% Offline** | Nenhuma API externa, tudo roda localmente |

## 🎯 Como Funciona

### Análise de E-mails
- ✅ Linguagem de urgência ("urgente", "imediato", "conta suspensa")
- ✅ Solicitação de dados sensíveis ("senha", "CPF", "cartão")
- ✅ Links suspeitos (encurtadores, domínios estranhos)
- ✅ Pontuação excessiva ("!!!", "???")
- ✅ Padrões clássicos de phishing

### Análise de URLs
- ✅ Verificação de HTTPS
- ✅ TLDs suspeitos (.xyz, .tk, .ml, .ga, .cf)
- ✅ Imitação de marcas conhecidas
- ✅ URLs com endereço IP
- ✅ Subdomínios excessivos
- ✅ URLs encurtadas (bit.ly, tinyurl, etc.)


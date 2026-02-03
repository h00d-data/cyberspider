# 🕷️ CyberSpider

**CyberSpider** é um sistema automatizado de coleta, correlação e análise de novas vulnerabilidades a partir 
de fontes públicas, integrando **Kill Chain**, **EPSS**, **NVD**, **CISA KEV**, **ExploitDB** e inteligência ofensiva.

> Desenvolvido por **h00d**  
> 🔗 https://github.com/h00d-data

---

## 🚀 Funcionalidades

- Coleta automática de novas vulnerabilidades
- Integração com:
  - Exploit-DB RSS
  - CISA KEV
  - NVD (CVSS)
  - EPSS (probabilidade real de exploração)
- Classificação automática de vulnerabilidades
- Geração de **Attack Path / Kill Chain**
- Sugestão de payloads ofensivos
- Detecção de suporte:
  - Metasploit
  - Nuclei
- Interface gráfica (PyQt6)
- Exportação de relatório em **DOCX** da vulnerabilidade para preenchimento posterior!

---

## 🧠 Fontes de Inteligência

- Exploit-DB
- CaveiraTech
- NVD (NIST)
- FIRST EPSS
- CISA Known Exploited Vulnerabilities

---

## 🖥️ Requisitos

- Python 3.10+
- Linux (Kali recomendado)

# Opcional (recomendado):
- msfconsole
- nuclei

⚙️ Configuração

- Configure sua API do NVD (opcional):
export NVD_API_KEY=YOUR_KEY

▶️ Como executar
python3 cyberspider.py

### Dependências
```bash
pip install -r requirements.txt
````

📄 Relatórios

- Exportação em .docx Inclui:

- CVSS
- EPSS
- CISA KEV
- Kill Chain

- Gráfico de risco (Impacto x Exploitabilidade)

⚠️ Aviso Legal

- Este projeto é destinado exclusivamente para fins educacionais, pesquisa e defesa. O uso indevido é de inteira responsabilidade do usuário.


🔥 CyberSpider — Informação vira ataque. Ataque vira defesa.

---

## 📘 docs/architecture.md 

```md
# CyberSpider Architecture

## Pipeline

1. Data Collection
   - RSS
   - HTML scraping
   - APIs públicas

2. Normalization
   - CVE detection
   - Vuln classification

3. Enrichment
   - NVD
   - EPSS
   - CISA KEV

4. Intelligence
   - Attack Path
   - Payload suggestion
   - Exploit availability

5. Output
   - GUI
   - DOCX Report


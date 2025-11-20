#!/bin/bash

# Script di Setup Completo per Macchina Penetration Testing - VERSIONE CORRETTA
# Testato su Ubuntu 22.04 LTS e Debian-based systems

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

TOOLS_DIR="/opt"
LOG_FILE="/var/log/pentest_setup.log"

# Funzione di log
log() {
    echo -e "${2}$1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> $LOG_FILE
}

# Verifica root
if [ "$EUID" -ne 0 ]; then 
    log "Esegui lo script come root: sudo bash $0" "$RED"
    exit 1
fi

# Salva l'utente reale (non root)
REAL_USER=${SUDO_USER:-$USER}
REAL_HOME=$(eval echo ~$REAL_USER)

log "========================================" "$GREEN"
log "  Setup Macchina Penetration Testing" "$GREEN"
log "========================================" "$GREEN"
log "User: $REAL_USER | Home: $REAL_HOME\n" "$BLUE"

# [1/13] Update sistema
log "[1/13] Aggiornamento sistema..." "$YELLOW"
apt update 2>&1 | tee -a $LOG_FILE
DEBIAN_FRONTEND=noninteractive apt upgrade -y 2>&1 | tee -a $LOG_FILE

# [2/13] Dipendenze base
log "[2/13] Installazione dipendenze base..." "$YELLOW"
apt install -y build-essential git curl wget vim nano net-tools \
    python3-pip python3-venv python3-dev golang-go openjdk-11-jdk \
    ruby-full perl cmake libssl-dev libpcap-dev libpq-dev \
    apt-transport-https ca-certificates gnupg lsb-release \
    software-properties-common 2>&1 | tee -a $LOG_FILE

# [3/13] Information Gathering
log "[3/13] Installazione tool Information Gathering..." "$YELLOW"

# Tool disponibili nei repository
apt install -y nmap masscan dnsenum whois dnsrecon fierce dmitry \
    2>&1 | tee -a $LOG_FILE || log "Alcuni pacchetti non disponibili, continuo..." "$YELLOW"

# TheHarvester da GitHub
if [ ! -d "$TOOLS_DIR/theHarvester" ]; then
    log "Installazione theHarvester..." "$BLUE"
    cd $TOOLS_DIR
    git clone https://github.com/laramies/theHarvester.git 2>&1 | tee -a $LOG_FILE
    cd theHarvester
    python3 -m pip install -r requirements/base.txt 2>&1 | tee -a $LOG_FILE
    chmod +x theHarvester.py
    ln -sf $TOOLS_DIR/theHarvester/theHarvester.py /usr/local/bin/theharvester
    log "✓ theHarvester installato" "$GREEN"
fi

# Sublist3r da GitHub
if [ ! -d "$TOOLS_DIR/Sublist3r" ]; then
    log "Installazione Sublist3r..." "$BLUE"
    cd $TOOLS_DIR
    git clone https://github.com/aboul3la/Sublist3r.git 2>&1 | tee -a $LOG_FILE
    cd Sublist3r
    python3 -m pip install -r requirements.txt 2>&1 | tee -a $LOG_FILE
    chmod +x sublist3r.py
    ln -sf $TOOLS_DIR/Sublist3r/sublist3r.py /usr/local/bin/sublist3r
    log "✓ Sublist3r installato" "$GREEN"
fi

# Amass
if ! command -v amass &> /dev/null; then
    log "Installazione Amass..." "$BLUE"
    if command -v snap &> /dev/null; then
        snap install amass 2>&1 | tee -a $LOG_FILE
    else
        go install -v github.com/OWASP/Amass/v3/...@master 2>&1 | tee -a $LOG_FILE
    fi
    log "✓ Amass installato" "$GREEN"
fi

# Python packages
python3 -m pip install --upgrade shodan recon-ng 2>&1 | tee -a $LOG_FILE

# [4/13] Vulnerability Scanning
log "[4/13] Installazione Vulnerability Scanners..." "$YELLOW"
apt install -y nikto wpscan 2>&1 | tee -a $LOG_FILE

# Nuclei
if ! command -v nuclei &> /dev/null; then
    log "Installazione Nuclei..." "$BLUE"
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>&1 | tee -a $LOG_FILE
    log "✓ Nuclei installato" "$GREEN"
fi

# [5/13] Web Application Testing
log "[5/13] Installazione Web Testing Tools..." "$YELLOW"
apt install -y zaproxy sqlmap gobuster wfuzz dirb wafw00f whatweb \
    2>&1 | tee -a $LOG_FILE

# Burp Suite Community (se disponibile)
apt install -y burpsuite 2>&1 | tee -a $LOG_FILE || log "Burpsuite non in repo, scarica manualmente" "$YELLOW"

# ffuf
if ! command -v ffuf &> /dev/null; then
    log "Installazione ffuf..." "$BLUE"
    go install github.com/ffuf/ffuf/v2@latest 2>&1 | tee -a $LOG_FILE
    log "✓ ffuf installato" "$GREEN"
fi

# XSStrike
if [ ! -d "$TOOLS_DIR/XSStrike" ]; then
    log "Installazione XSStrike..." "$BLUE"
    cd $TOOLS_DIR
    git clone https://github.com/s0md3v/XSStrike.git 2>&1 | tee -a $LOG_FILE
    cd XSStrike
    python3 -m pip install -r requirements.txt 2>&1 | tee -a $LOG_FILE
    chmod +x xsstrike.py
    ln -sf $TOOLS_DIR/XSStrike/xsstrike.py /usr/local/bin/xsstrike
    log "✓ XSStrike installato" "$GREEN"
fi

# [6/13] Exploitation Tools
log "[6/13] Installazione Exploitation Tools..." "$YELLOW"

# Metasploit Framework
if ! command -v msfconsole &> /dev/null; then
    log "Installazione Metasploit Framework..." "$BLUE"
    curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > /tmp/msfinstall 2>&1 | tee -a $LOG_FILE
    chmod 755 /tmp/msfinstall
    /tmp/msfinstall 2>&1 | tee -a $LOG_FILE
    log "✓ Metasploit installato" "$GREEN"
fi

apt install -y exploitdb 2>&1 | tee -a $LOG_FILE

# Social Engineering Toolkit
apt install -y set 2>&1 | tee -a $LOG_FILE || log "SET non disponibile nei repo" "$YELLOW"

# [7/13] Password Cracking
log "[7/13] Installazione Password Tools..." "$YELLOW"
apt install -y hydra john hashcat medusa crunch cewl \
    2>&1 | tee -a $LOG_FILE

# Patator
python3 -m pip install patator 2>&1 | tee -a $LOG_FILE

# Wordlists
apt install -y wordlists 2>&1 | tee -a $LOG_FILE || log "Pacchetto wordlists non trovato" "$YELLOW"

# [8/13] Network Analysis
log "[8/13] Installazione Network Tools..." "$YELLOW"
apt install -y wireshark tcpdump dsniff netcat-traditional ncat socat \
    2>&1 | tee -a $LOG_FILE

# Ettercap
apt install -y ettercap-graphical ettercap-text-only 2>&1 | tee -a $LOG_FILE

# Bettercap
if ! command -v bettercap &> /dev/null; then
    log "Installazione Bettercap..." "$BLUE"
    apt install -y bettercap 2>&1 | tee -a $LOG_FILE || {
        # Se non nei repo, installa da binary
        wget https://github.com/bettercap/bettercap/releases/latest/download/bettercap_linux_amd64_*.zip -O /tmp/bettercap.zip 2>&1 | tee -a $LOG_FILE
        unzip /tmp/bettercap.zip -d /tmp/ 2>&1 | tee -a $LOG_FILE
        mv /tmp/bettercap /usr/local/bin/
        chmod +x /usr/local/bin/bettercap
    }
    log "✓ Bettercap installato" "$GREEN"
fi

# Responder
apt install -y responder 2>&1 | tee -a $LOG_FILE || {
    if [ ! -d "$TOOLS_DIR/Responder" ]; then
        log "Installazione Responder da GitHub..." "$BLUE"
        cd $TOOLS_DIR
        git clone https://github.com/lgandx/Responder.git 2>&1 | tee -a $LOG_FILE
        chmod +x Responder/Responder.py
        ln -sf $TOOLS_DIR/Responder/Responder.py /usr/local/bin/responder
        log "✓ Responder installato" "$GREEN"
    fi
}

# [9/13] Wireless Tools
log "[9/13] Installazione Wireless Tools..." "$YELLOW"
apt install -y aircrack-ng reaver kismet 2>&1 | tee -a $LOG_FILE

# Wifite
apt install -y wifite 2>&1 | tee -a $LOG_FILE || {
    if [ ! -d "$TOOLS_DIR/wifite2" ]; then
        log "Installazione Wifite2 da GitHub..." "$BLUE"
        cd $TOOLS_DIR
        git clone https://github.com/derv82/wifite2.git 2>&1 | tee -a $LOG_FILE
        cd wifite2
        python3 setup.py install 2>&1 | tee -a $LOG_FILE
        log "✓ Wifite2 installato" "$GREEN"
    fi
}

# [10/13] Post-Exploitation
log "[10/13] Installazione Post-Exploitation Tools..." "$YELLOW"

# Impacket
python3 -m pip install impacket 2>&1 | tee -a $LOG_FILE

# Evil-WinRM
if ! command -v evil-winrm &> /dev/null; then
    log "Installazione Evil-WinRM..." "$BLUE"
    gem install evil-winrm 2>&1 | tee -a $LOG_FILE
    log "✓ Evil-WinRM installato" "$GREEN"
fi

# PEASS (LinPEAS/WinPEAS)
log "Download PEASS scripts..." "$BLUE"
mkdir -p $TOOLS_DIR/PEASS
wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh \
    -O $TOOLS_DIR/PEASS/linpeas.sh 2>&1 | tee -a $LOG_FILE
wget -q https://github.com/carlospolop/PEASS-ng/releases/latest/download/winPEASx64.exe \
    -O $TOOLS_DIR/PEASS/winPEASx64.exe 2>&1 | tee -a $LOG_FILE
chmod +x $TOOLS_DIR/PEASS/linpeas.sh
log "✓ PEASS scaricato in $TOOLS_DIR/PEASS/" "$GREEN"

# Chisel (tunneling)
if ! command -v chisel &> /dev/null; then
    log "Download Chisel..." "$BLUE"
    CHISEL_VERSION=$(curl -s https://api.github.com/repos/jpillora/chisel/releases/latest | grep -Po '"tag_name": "v\K[^"]*')
    wget -q https://github.com/jpillora/chisel/releases/latest/download/chisel_${CHISEL_VERSION}_linux_amd64.gz \
        -O /tmp/chisel.gz 2>&1 | tee -a $LOG_FILE
    gunzip /tmp/chisel.gz
    mv /tmp/chisel /usr/local/bin/
    chmod +x /usr/local/bin/chisel
    log "✓ Chisel installato" "$GREEN"
fi

# [11/13] Reverse Engineering
log "[11/13] Installazione Reverse Engineering Tools..." "$YELLOW"
apt install -y radare2 gdb binutils strace ltrace ghex hexedit \
    2>&1 | tee -a $LOG_FILE

# pwndbg per GDB
if [ ! -d "$TOOLS_DIR/pwndbg" ]; then
    log "Installazione pwndbg..." "$BLUE"
    cd $TOOLS_DIR
    git clone https://github.com/pwndbg/pwndbg 2>&1 | tee -a $LOG_FILE
    cd pwndbg
    ./setup.sh 2>&1 | tee -a $LOG_FILE
    log "✓ pwndbg installato" "$GREEN"
fi

# [12/13] Forensics
log "[12/13] Installazione Forensics Tools..." "$YELLOW"
apt install -y binwalk steghide exiftool foremost strings \
    2>&1 | tee -a $LOG_FILE

# Autopsy (opzionale, pesante)
apt install -y autopsy 2>&1 | tee -a $LOG_FILE || log "Autopsy non installato (opzionale)" "$YELLOW"

# Volatility3
python3 -m pip install volatility3 2>&1 | tee -a $LOG_FILE

# [13/13] Configurazioni finali
log "[13/13] Configurazioni finali..." "$YELLOW"

# PATH per Go binaries
if ! grep -q "export PATH=\$PATH:/root/go/bin" /root/.bashrc; then
    echo 'export PATH=$PATH:/root/go/bin' >> /root/.bashrc
fi
if ! grep -q "export PATH=\$PATH:$REAL_HOME/go/bin" $REAL_HOME/.bashrc; then
    echo "export PATH=\$PATH:$REAL_HOME/go/bin" >> $REAL_HOME/.bashrc
    chown $REAL_USER:$REAL_USER $REAL_HOME/.bashrc
fi

# Directory struttura
mkdir -p $TOOLS_DIR/custom-tools
mkdir -p $TOOLS_DIR/wordlists
mkdir -p $TOOLS_DIR/exploits
mkdir -p /root/pentest/{recon,scans,exploits,loot,reports}

# SecLists wordlists
if [ ! -d "$TOOLS_DIR/wordlists/SecLists" ]; then
    log "Download SecLists wordlists (può richiedere tempo)..." "$BLUE"
    cd $TOOLS_DIR/wordlists
    git clone --depth 1 https://github.com/danielmiessler/SecLists.git 2>&1 | tee -a $LOG_FILE
    log "✓ SecLists scaricato" "$GREEN"
fi

# PayloadsAllTheThings
if [ ! -d "$TOOLS_DIR/PayloadsAllTheThings" ]; then
    log "Download PayloadsAllTheThings..." "$BLUE"
    cd $TOOLS_DIR
    git clone --depth 1 https://github.com/swisskyrepo/PayloadsAllTheThings.git 2>&1 | tee -a $LOG_FILE
    log "✓ PayloadsAllTheThings scaricato" "$GREEN"
fi

# Setup Metasploit database
if command -v msfdb &> /dev/null; then
    log "Inizializzazione database Metasploit..." "$BLUE"
    systemctl start postgresql 2>&1 | tee -a $LOG_FILE
    systemctl enable postgresql 2>&1 | tee -a $LOG_FILE
    msfdb init 2>&1 | tee -a $LOG_FILE || log "Database MSF già inizializzato" "$YELLOW"
fi

# Wireshark permessi
if [ -f "/usr/bin/wireshark" ]; then
    log "Configurazione permessi Wireshark..." "$BLUE"
    DEBIAN_FRONTEND=noninteractive dpkg-reconfigure wireshark-common 2>&1 | tee -a $LOG_FILE
    usermod -a -G wireshark $REAL_USER 2>/dev/null || true
fi

# Aliases utili
log "Creazione aliases..." "$BLUE"
cat >> $REAL_HOME/.bash_aliases << 'EOF'
# Penetration Testing Aliases
alias nse='ls /usr/share/nmap/scripts/ | grep'
alias serve='python3 -m http.server 8000'
alias myip='curl -s ifconfig.me'
alias ports='netstat -tulanp'
alias listening='lsof -i -P -n | grep LISTEN'
alias scan='nmap -sV -sC'
alias dirsearch='gobuster dir -u'
alias msfconsole='msfconsole -q'
alias ll='ls -lah'

# Directory shortcuts
alias cdpentest='cd /root/pentest'
alias cdtools='cd /opt'
alias cdwordlists='cd /opt/wordlists'
EOF
chown $REAL_USER:$REAL_USER $REAL_HOME/.bash_aliases

# Update locate database
updatedb 2>&1 | tee -a $LOG_FILE

# Cleanup
log "Pulizia sistema..." "$YELLOW"
apt autoremove -y 2>&1 | tee -a $LOG_FILE
apt clean 2>&1 | tee -a $LOG_FILE

# Summary
log "\n========================================" "$GREEN"
log "  Installazione Completata!" "$GREEN"
log "========================================\n" "$GREEN"

log "Tool Installati:" "$GREEN"
echo "  ✓ Information Gathering (nmap, masscan, theharvester, sublist3r, amass)"
echo "  ✓ Vulnerability Scanning (nikto, nuclei, wpscan)"
echo "  ✓ Web Testing (burpsuite, sqlmap, gobuster, ffuf, xsstrike)"
echo "  ✓ Exploitation (metasploit, searchsploit, SET)"
echo "  ✓ Password Cracking (hydra, john, hashcat, medusa)"
echo "  ✓ Network Analysis (wireshark, ettercap, bettercap, responder)"
echo "  ✓ Wireless (aircrack-ng, wifite, reaver, kismet)"
echo "  ✓ Post-Exploitation (impacket, evil-winrm, PEASS, chisel)"
echo "  ✓ Reverse Engineering (radare2, gdb+pwndbg)"
echo "  ✓ Forensics (binwalk, volatility3, steghide, exiftool)"

log "\nDirectory Importanti:" "$YELLOW"
echo "  - Tools: $TOOLS_DIR/"
echo "  - Wordlists: $TOOLS_DIR/wordlists/"
echo "  - SecLists: $TOOLS_DIR/wordlists/SecLists/"
echo "  - PayloadsAllTheThings: $TOOLS_DIR/PayloadsAllTheThings/"
echo "  - PEASS: $TOOLS_DIR/PEASS/"
echo "  - Progetti: /root/pentest/"
echo "  - Log installazione: $LOG_FILE"

log "\nProssimi Passi:" "$YELLOW"
echo "  1. Riavvia la shell: exec bash"
echo "  2. Oppure: source ~/.bashrc"
echo "  3. Aggiorna Nuclei templates: nuclei -update-templates"
echo "  4. Configura Burp Suite: burpsuite"
echo "  5. Test Metasploit: msfconsole"
echo "  6. Verifica tool: bash /opt/test_tools.sh (se disponibile)"

log "\nComandi Utili:" "$BLUE"
echo "  - Lista tool: ls /opt/"
echo "  - Cerca wordlist: locate rockyou.txt"
echo "  - Update tutto: apt update && apt upgrade -y"
echo "  - Documentazione: man <tool>"

log "\n✓ Setup completato con successo!" "$GREEN"
log "Log salvato in: $LOG_FILE\n" "$BLUE"

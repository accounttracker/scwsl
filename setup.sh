#!/bin/bash
if [ "${EUID}" -ne 0 ]; then
		echo "You need to run this script as root"
		exit 1
fi
if [ "$(systemd-detect-virt)" == "openvz" ]; then
		echo "OpenVZ is not supported"
		exit 1
fi
# ==========================================
# Color
RED='\033[0;31m'
NC='\033[0m'
GREEN='\033[0;32m'
ORANGE='\033[0;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
LIGHT='\033[0;37m'
# ==========================================



# Getting
MYIP=$(wget -qO- ipinfo.io/ip);

#if [ -f "/etc/v2ray/domain" ]; then
if [ -f "/etc/xray/domain" ]; then
echo "Script Already Installed"
exit 0
fi
mkdir /var/lib/wisnucs;
echo "IP=" >> /var/lib/wisnucs/ipvps.conf
wget https://raw.githubusercontent.com/anzclan/scwsl/main/ssh/cf.sh && chmod +x cf.sh && ./cf.sh
wget https://raw.githubusercontent.com/anzclan/scwsl/main/xray/ins-xray.sh && chmod +x ins-xray.sh && screen -S xray ./ins-xray.sh
wget https://raw.githubusercontent.com/anzclan/scwsl/main/ssh/ssh-vpn.sh && chmod +x ssh-vpn.sh && screen -S ssh-vpn ./ssh-vpn.sh
wget https://raw.githubusercontent.com/anzclan/scwsl/main/backup/set-br.sh && chmod +x set-br.sh && ./set-br.sh
wget https://raw.githubusercontent.com/anzclan/scwsl/main/websocket/python.sh && chmod +x python.sh && ./python.sh
wget https://raw.githubusercontent.com/anzclan/scwsl/main/ohp/ohp.sh && chmod +x ohp.sh && ./ohp.sh

rm -f /root/ssh-vpn.sh
rm -f /root/ins-xray.sh
rm -f /root/ipsec.sh
rm -f /root/set-br.sh
rm -f /root/python.sh
rm -f /root/ohp.sh

systemctl daemon-reload
systemctl enable autosett

history -c
echo "1.2" > /home/ver
echo " "
echo "Installation has been completed!!"
echo ""  |tee -a log-install.txt
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;41m           🔰 SETUP SERVER BY ZEROSSL 🔰            \E[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo ""  |tee -a log-install.txt
echo -e " 🔰 >>> Service & Port" |tee -a log-install.txt
echo -e " 🔰 PORT OPENSSH : 22" |tee -a log-install.txt
echo -e " 🔰 PORT OPENVPN TCP : 700" |tee -a log-install.txt
echo -e " 🔰 PORT OPENVPN UDP : 800" |tee -a log-install.txt
echo -e " 🔰 PORT OPENVPN SSL : 443" |tee -a log-install.txt
echo -e " 🔰 PORT STUNNEL5 : 500, 600" |tee -a log-install.txt
echo -e " 🔰 PORT DROPBEAR : 300, 200" |tee -a log-install.txt
echo -e " 🔰 PORT SQUID : 3128, 3228" |tee -a log-install.txt
echo -e " 🔰 UDPGW : 9100, 9200, 9300-9900" |tee -a log-install.txt
echo -e " 🔰 NGINX : 88" |tee -a log-install.txt
echo -e " 🔰 WIREGUARD : 591" |tee -a log-install.txt
echo -e " 🔰 L2TP/IPSEC VPN : 1701" |tee -a log-install.txt
echo -e " 🔰 PPTP VPN : 1732" |tee -a log-install.txt
echo -e " 🔰 SSTP VPN : 666" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS-R : 1444-1543" |tee -a log-install.txt
echo -e " 🔰 SS-OBFS TLS : 2444-2943" |tee -a log-install.txt
echo -e " 🔰 SS-OBFS HTTP : 2944-3442" |tee -a log-install.txt
echo -e " 🔰 XRAY SHADOWSOCKS : 333" |tee -a log-install.txt
echo -e " 🔰 XRAY MTPROTO : 111" |tee -a log-install.txt
echo -e " 🔰 WEBSOCKET TLS : 2087" |tee -a log-install.txt
echo -e " 🔰 WEBSOCKET NON TLS : 2086" |tee -a log-install.txt
echo -e " 🔰 PORT OVPN WS TLS : 2083" |tee -a log-install.txt
echo -e " 🔰 PORT OVPN WS NON TLS : 8080" |tee -a log-install.txt
echo -e " 🔰 OHP SSH : 8181" |tee -a log-install.txt
echo -e " 🔰 OHP DROPBEAR : 8282" |tee -a log-install.txt
echo -e " 🔰 OHP OVPN : 8383" |tee -a log-install.txt
echo -e " 🔰 VMESS WS TLS : 443" |tee -a log-install.txt
echo -e " 🔰 VMESS WS NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 VMESS GRPC TLS: 443" |tee -a log-install.txt
echo -e " 🔰 VMESS GRPC NON TLS: 80" |tee -a log-install.txt
echo -e " 🔰 VMESS H2C TLS : 2005" |tee -a log-install.txt
echo -e " 🔰 VMESS HTTP TLS : 8443" |tee -a log-install.txt
echo -e " 🔰 VMESS QUIC TLS : 801" |tee -a log-install.txt
echo -e " 🔰 VMESS KCP TLS : 802" |tee -a log-install.txt
echo -e " 🔰 VMESS HTTP NON TLS : 808" |tee -a log-install.txt
echo -e " 🔰 VLESS XTLS : 8443" |tee -a log-install.txt
echo -e " 🔰 VLESS GFW : 8443" |tee -a log-install.txt
echo -e " 🔰 VLESS WS TLS : 443" |tee -a log-install.txt
echo -e " 🔰 VLESS WS NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 VLESS GRPC TLS : 443" |tee -a log-install.txt
echo -e " 🔰 VLESS GRPC NON TLS: 1001" |tee -a log-install.txt
echo -e " 🔰 VLESS H2C TLS : 1150" |tee -a log-install.txt
echo -e " 🔰 VLESS QUIC TLS: 401" |tee -a log-install.txt
echo -e " 🔰 VLESS KCP TLS : 402" |tee -a log-install.txt
echo -e " 🔰 VLESS HTTP TLS : 8443" |tee -a log-install.txt
echo -e " 🔰 VLESS HTTP NON TLS : 8088" |tee -a log-install.txt
echo -e " 🔰 TROJAN GO : 2053" |tee -a log-install.txt
echo -e " 🔰 TROJAN GRPC : 443" |tee -a log-install.txt
echo -e " 🔰 TROJAN HTTP TLS : 8443" |tee -a log-install.txt
echo -e " 🔰 TROJAN HTTP NON TLS : 880" |tee -a log-install.txt
echo -e " 🔰 TROJAN H2C : 1120" |tee -a log-install.txt
echo -e " 🔰 TROJAN XTLS : 1440" |tee -a log-install.txt
echo -e " 🔰 TROJAN QUIC TLS : 201" |tee -a log-install.txt
echo -e " 🔰 TROJAN KCP TLS : 202" |tee -a log-install.txt
echo -e " 🔰 TROJAN GFW : 8443" |tee -a log-install.txt
echo -e " 🔰 TROJAN WS TLS : 443" |tee -a log-install.txt
echo -e " 🔰 TROJAN WS NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 SOCKS5 WS TLS : 443" |tee -a log-install.txt
echo -e " 🔰 SOCKS5 WS NON TLS  : 80" |tee -a log-install.txt
echo -e " 🔰 SOCKS5 GRPC TLS : 443" |tee -a log-install.txt
echo -e " 🔰 SOCKS5 GRPC NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 SOCKS5 TCP TLS : 10809 |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS TCP TLS : 414" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS WS TLS : 443" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS WS NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS GRPC TLS : 443" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS GRPC NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS 2022 TCP TLS : 212" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS 2022 WS NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS 2022 WS TLS : 443" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS 2022 GRPC TLS : 443" |tee -a log-install.txt
echo -e " 🔰 SHADOWSOCKS 2022 GRPC NON TLS : 80" |tee -a log-install.txt
echo -e " 🔰 XRAY MT PROTO : 111" |tee -a log-install.txt
echo ""  |tee -a log-install.txt
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e " 🔰>> Server Information & Other Features"                  |tee -a log-install.txt
echo -e " 🔰 Timezone                : Asia/Jakarta (GMT +7)"        |tee -a log-install.txt
echo -e " 🔰 Fail2Ban                : [ON]"                         |tee -a log-install.txt
echo -e " 🔰 Dflate                  : [ON]"                         |tee -a log-install.txt
echo -e " 🔰 IPtables                : [ON]"                         |tee -a log-install.txt
echo -e " 🔰 Auto-Reboot             : [ON]"                         |tee -a log-install.txt
echo -e " 🔰 IPv6                    : [OFF]"                        |tee -a log-install.txt
echo -e " 🔰 Autoreboot On 04.00 GMT +7"                             |tee -a log-install.txt
echo -e " 🔰 Autobackup Data"                                        |tee -a log-install.txt
echo -e " 🔰 Restore Data"                                           |tee -a log-install.txt
echo -e " 🔰 Auto Delete Expired Account"                            |tee -a log-install.txt
echo -e " 🔰 NGUTER,CENTRAL JAVA,INDONESIA"                          |tee -a log-install.txt
echo -e " 🔰 Editing and Scan Typo by GANDRING"                      |tee -a log-install.txt
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"
echo -e "\E[44;1;41m           🔰 SOLO THE SPIRIT OF JAVA 🔰            \E[0m"
echo -e "\033[1;36m━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\033[0m"  
echo -e " 🔰 Installation Log --> /root/log-install.txt" |tee -a log-install.txt
echo " Reboot 5 Sec"
sleep 5
rm -f setup.sh
reboot

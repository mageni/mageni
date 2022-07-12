###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_131.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.131
#
# Authors:
# Thomas Rotter <thomas.rotter@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.95074");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05131.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_IIS_Protect_SynAttack.nasl", "GSHB/GSHB_WMI_NtpServer.nasl", "GSHB/GSHB_WMI_SNMP_Communities.nasl");
  script_require_keys("WMI/WMI_OSVER");
  script_tag(name:"summary", value:"IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.131: Absicherung von IP-Protokollen unter Windows Server 2003\n';

gshbm =  "IT-Grundschutz M5.131: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
log = get_kb_item("WMI/cps/GENERAL/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
NTLMMinServerSec = get_kb_item("WMI/cps/NTLMMinServerSec");
requiresignorseal = get_kb_item("WMI/cps/requiresignorseal");
requirestrongkey = get_kb_item("WMI/cps/requirestrongkey");
RequireSecuritySignatureWs = get_kb_item("WMI/cps/RequireSecuritySignatureWs");
EnablePlainTextPassword = get_kb_item("WMI/cps/EnablePlainTextPassword");
RequireSecuritySignatureSvr = get_kb_item("WMI/cps/RequireSecuritySignatureSvr");
EnableSecuritySignatureSvr = get_kb_item("WMI/cps/EnableSecuritySignatureSvr");
NoLMHash = get_kb_item("WMI/cps/NoLMHash");
lmcomplevel = get_kb_item("WMI/scp/LMCompatibilityLevel");
LDAPClientIntegrity = get_kb_item("WMI/cps/LDAPClientIntegrity");
NTLMMinClientSec = get_kb_item("WMI/cps/NTLMMinClientSec");

DisableIPSourceRouting = get_kb_item("WMI/cps/DisableIPSourceRouting");
EnableDeadGWDetect = get_kb_item("WMI/cps/EnableDeadGWDetect");
EnableICMPRedirect = get_kb_item("WMI/cps/EnableICMPRedirect");
NoNameReleaseOnDemand = get_kb_item("WMI/cps/NoNameReleaseOnDemand");
PerformRouterDiscovery = get_kb_item("WMI/cps/PerformRouterDiscovery");
SynAttackProtect = get_kb_item("WMI/cps/SynAttackProtect");
TcpMaxConnectResponseRetransmissions = get_kb_item("WMI/cps/TcpMaxConnectResponseRetransmissions");
TcpMaxDataRetransmissions = get_kb_item("WMI/cps/TcpMaxDataRetransmissions");
KeepAliveTime = get_kb_item("WMI/cps/KeepAliveTime");

TcpMaxPortsExhausted = get_kb_item("WMI/TcpMaxPortsExhausted");
MinimumDynamicBacklog = get_kb_item("WMI/MinimumDynamicBacklog");
MaximumDynamicBacklog = get_kb_item("WMI/MaximumDynamicBacklog");
EnableDynamicBacklog = get_kb_item("WMI/EnableDynamicBacklog");
DynamicBacklogGrowthDelta = get_kb_item("WMI/DynamicBacklogGrowthDelta");

ntpserver = get_kb_item("WMI/NtpServer");
ntpserver = tolower(ntpserver);
domain = get_kb_item("WMI/WMI_WindowsDomain");
domain = tolower(domain);

if (ntpserver >!< "none" && ntpserver >!< "error") ntpserver = split(ntpserver, sep:",", keep:0);


SNMPCommunities = get_kb_item("WMI/SNMPCommunities");
SNMPCommunities = tolower(SNMPCommunities);

DefaultCommunity = "false";
SNMPCommunitiesSP = split(SNMPCommunities, sep:'|', keep:0);

for(i=0; i<max_index(SNMPCommunitiesSP); i++)
{
  if (SNMPCommunitiesSP[i] == "public" || SNMPCommunitiesSP[i] == "private")
  {
    DefCom = "true";
    set_kb_item(name:"GSHB/M5_131/DefCom" + i, value:DefCom);

    ExistComm += SNMPCommunitiesSP[i] + '\n' ;
    # set_kb_item(name:"GSHB/M5_131/ExistComm" + i, value:ExistComm);
  }
  else DefCom = "false";
  if (DefCom == "true" && DefaultCommunity == "true")
  {
    DefaultCommunity = "true";
  }
  else if (DefCom == "false" && DefaultCommunity == "true")
  {
    DefaultCommunity = "true";
  }
  else if (DefCom == "true" && DefaultCommunity == "false")
  {
    DefaultCommunity = "true";
  }
  else DefaultCommunity = "false";
}

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein Microsoft System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgef¸hrt werden.");
}else if(OSVER != '5.2' || OSNAME >< 'Microsoft(R) Windows(R) XP Professional x64 Edition'){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows 2003 Server.");
}else if(NTLMMinServerSec == "537395248" && requiresignorseal == "1" && requirestrongkey == "1" && RequireSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && RequireSecuritySignatureSvr == "1" && EnableSecuritySignatureSvr == "1" && NoLMHash == "1" && lmcomplevel >= "5" && LDAPClientIntegrity == "1" && NTLMMinClientSec == "537395248" && domain >< ntpserver[0] && DisableIPSourceRouting == "2" && EnableDeadGWDetect =="0" && EnableICMPRedirect == "0" && NoNameReleaseOnDemand == "1" && PerformRouterDiscovery == "0" && SynAttackProtect =="1" && TcpMaxConnectResponseRetransmissions == "3" && TcpMaxDataRetransmissions == "3" && KeepAliveTime == "300000" && TcpMaxPortsExhausted == "5" && MinimumDynamicBacklog == "20" && MaximumDynamicBacklog == "20000" && EnableDynamicBacklog == "1" && DynamicBacklogGrowthDelta == "10" && DefaultCommunity == "false")
{
  result = string("erf¸llt");
  desc = string("Die Sicherheitseinstellungen stimmen mit der Maﬂnahme M5.131 ¸berein.");
}else{
  result = string("nicht erf¸llt");
  if (DisableIPSourceRouting != "2") val = val + '\n' + "MSS: (DisableIPSourceRouting) IP source routing protection\nlevel (protects against packet spoofing)\n";
  if (EnableDeadGWDetect != "0") val = val + '\n' + "MSS: (EnableDeadGWDetect) Allow automatic detection of dead\nnetwork gateways (could lead to DoS)\n";
  if (EnableICMPRedirect != "0") val = val + '\n' + "MSS: (EnableICMPRedirect) Allow ICMP redirects to override OSPF\ngenerated routes\n";
  if (EnablePlainTextPassword != "0") val = val + '\n' + "Microsoft-Netzwerk (Client): Unverschl¸sseltes Kennwort an\nSMB-Server von Drittanbietern senden\n";
  if (EnableSecuritySignatureSvr != "1") val = val + '\n' + "Microsoft-Netzwerk (Server): Kommunikation digital signieren\n(wenn Client zustimmt)\n";
  if (KeepAliveTime != "300000") val = val + '\n' + "MSS: (KeepAliveTime) How often keep-alive packets are sent\nin milliseconds\n";
  if (LDAPClientIntegrity != "1") val = val + '\n' + "Netzwerksicherheit: Signaturanforderungen f¸r LDAP-Clients\n";
  if (lmcomplevel != "5") val = val + '\n' + "Netzwerksicherheit: LAN Manager-Authentifizierungsebene\n";
  if (NoLMHash != "1") val = val + '\n' + "Netzwerksicherheit: Keine LAN Manager-Hashwerte f¸r n‰chste\nKennwort‰nderung speichern\n";
  if (NoNameReleaseOnDemand != "1") val = val + '\n' + "MSS: (NoNameReleaseOnDemand) Allow the computer to ignore\nNetBIOS name release requests except from WINS servers\n";
  if (NTLMMinClientSec != "537395248") val = val + '\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f¸r\nNTLM-SSP-basierte Clients (einschlieﬂlich sicherer RPC-Clients)\n";
  if (NTLMMinServerSec != "537395248") val = val + '\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit f¸r\nNTLM-SSP-basierte Server (einschlieﬂlich sicherer RPC-Server)\n";
  if (PerformRouterDiscovery != "0") val = val + '\n' + "MSS: (PerformRouterDiscovery) Allow IRDP to detect and\nconfigure Default Gateway addresses (could lead to DoS)\n";
  if (RequireSecuritySignatureSvr != "1") val = val + '\n' + "Microsoft-Netzwerk (Client): Kommunikation digital\nsignieren (immer)\n";
  if (RequireSecuritySignatureWs != "1") val = val + '\n' + "Microsoft-Netzwerk (Server): Kommunikation digital\nsignieren (immer)\n";
  if (requiresignorseal != "1") val = val + '\n' + "Dom‰nenmitglied: Daten des sicheren Kanals digital\nverschl¸sseln oder signieren (immer)\n";
  if (requirestrongkey != "1") val = val + '\n' + "Dom‰nenmitglied: Starker Sitzungsschl¸ssel erforderlich\n(Windows 2000 oder hˆher)";
  if (SynAttackProtect != "1") val = val + '\n' + "MSS: (SynAttackProtect) Syn attack protection level\n(protects against DoS)\n";
  if (TcpMaxConnectResponseRetransmissions != "3") val = val + '\n' + "MSS: (TCPMaxConnectResponseRetransmissions) SYN-ACK\nretransmissions when a connection request is not acknowledged\n";
  if (TcpMaxDataRetransmissions != "3") val = val + '\n' + "MSS: (TCPMaxDataRetransmissions) How many times unacknowledged\ndata is retransmitted (3 recommended, 5 is default)\n";
  if (TcpMaxPortsExhausted != "5") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\tcpip\\nParameters\TcpMaxPortsExhausted\n";
  if (DynamicBacklogGrowthDelta != "10") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\\nParameters\DynamicBacklogGrowthDelta\n";
  if (EnableDynamicBacklog != "1") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\\nParameters\EnableDynamicBacklog\n";
  if (MaximumDynamicBacklog != "20000") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\\nParameters\MaximumDynamicBacklog\n";
  if (MinimumDynamicBacklog != "20") val = val + '\n' + "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\AFD\\nParameters\MinimumDynamicBacklog\n";
  if (domain >!< ntpserver[0]) val = val + '\n' + "Auf dem System wurde ein externer NTP-Server hinterlegt:\n" + ntpserver[0] + '\n';
  if (DefaultCommunity != "false") val = val + '\n' + "Folgende Default Communities existieren:\n" + ExistComm;

  desc = string("Die Sicherheitseinstellungen stimmen nicht mit der Maﬂnahme\nM5.123 ¸berein. Folgende Einstellungen sind nicht wie gefordert\numgesetzt:\n" + val);
}

set_kb_item(name:"GSHB/M5_131/result", value:result);
set_kb_item(name:"GSHB/M5_131/desc", value:desc);
set_kb_item(name:"GSHB/M5_131/name", value:name);


silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_131');

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_277.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 4.277
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
  script_oid("1.3.6.1.4.1.25623.1.0.94223");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows-Servern");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04277.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/WMI_OSVER");
  script_tag(name:"summary", value:"IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows-Servern.

Stand: 14. Ergänzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.277: Absicherung der SMB-, LDAP- und RPC-Kommunikation unter Windows-Servern\n';

gshbm =  "IT-Grundschutz M4.277: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
log = get_kb_item("WMI/cps/GENERAL/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
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


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgeführt werden.");
}else if(OSTYPE < 2){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows Server.");
}else if (NTLMMinServerSec == "537395248" && requiresignorseal == "1" && requirestrongkey == "1" && RequireSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && RequireSecuritySignatureSvr == "1" && EnableSecuritySignatureSvr == "1" && NoLMHash == "1" && lmcomplevel >= "5" && LDAPClientIntegrity == "1" && NTLMMinClientSec == "537395248")
{
  result = string("erfüllt");
  desc = string("Die Sicherheitseinstellung stimmen mit der Maßnahme\nM4.277 überein.");
}else{
  result = string("nicht erfüllt");
  if (NTLMMinServerSec != "537395248") val = val + '\n\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit für\nNTLM-SSP-basierte Server (einschließlich sicherer\nRPC-Server)";
  if (requiresignorseal != "1") val = val + '\n\n' + "Domänenmitglied: Daten des sicheren Kanals digital\nverschlüsseln oder signieren (immer)";
  if (requirestrongkey != "1") val = val + '\n\n' + "Domänenmitglied: Starker Sitzungsschlüssel erforder-\nlich (Windows 2000 oder höher)";
  if (RequireSecuritySignatureWs != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Kommunikation digital\nsignieren (immer)";
  if (EnablePlainTextPassword != "0") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Unverschlüsseltes\nKennwort an SMB-Server von Drittanbietern senden";
  if (RequireSecuritySignatureSvr != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Client): Kommunikation digital\nsignieren (immer)";
  if (EnableSecuritySignatureSvr != "1") val = val + '\n\n' + "Microsoft-Netzwerk (Server): Kommunikation digital\nsignieren (wenn Client zustimmt)";
  if (NoLMHash != "1") val = val + '\n\n' + "Netzwerksicherheit: Keine LAN Manager-Hashwerte für\nnächste Kennwortänderung speichern";
  if (lmcomplevel != "5") val = val + '\n\n' + "Netzwerksicherheit: LAN Manager-Authentifizierungs-\nebene";
  if (LDAPClientIntegrity != "1") val = val + '\n\n' + "Netzwerksicherheit: Signaturanforderungen für LDAP-\nClients";
  if (NTLMMinClientSec != "537395248") val = val + '\n\n' + "Netzwerksicherheit: Minimale Sitzungssicherheit für\nNTLM-SSP-basierte Clients (einschließlich sicherer\nRPC-Clients)";

  desc = string("Die Sicherheitseinstellung stimmen nicht mit der\nMaßnahme M4.277 Überein. Folgende Einstellungen sind\nnicht wie im Dokument 'Windows Server 2003 Security\nBaseline Settings' gefordert umgesetzt: " + val);
}

set_kb_item(name:"GSHB/M4_277/result", value:result);
set_kb_item(name:"GSHB/M4_277/desc", value:desc);
set_kb_item(name:"GSHB/M4_277/name", value:name);


silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_277');

exit(0);

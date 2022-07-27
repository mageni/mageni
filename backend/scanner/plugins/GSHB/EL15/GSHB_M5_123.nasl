###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_123.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 15. EL, Maßnahme 5.123
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
  script_oid("1.3.6.1.4.1.25623.1.0.95073");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M5.123: Absicherung der Netzkommunikation unter Windows");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05123.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_require_keys("WMI/WMI_OSVER");
  script_tag(name:"summary", value:"IT-Grundschutz M5.123: Absicherung der Netzkommunikation unter Windows.

Stand: 15. Ergänzungslieferung (15. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.123 Absicherung der Netzkommunikation unter Windows\n';

gshbm =  "IT-Grundschutz M5.123: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
log = get_kb_item("WMI/cps/GENERAL/log");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
disablepasswordchange = get_kb_item("WMI/cps/disablepasswordchange");
maximumComppasswordage = get_kb_item("WMI/cps/maximumComppasswordage");
requirestrongkey = get_kb_item("WMI/cps/requirestrongkey");
requiresignorseal = get_kb_item("WMI/cps/requiresignorseal");
sealsecurechannel = get_kb_item("WMI/cps/sealsecurechannel");
signsecurechannel = get_kb_item("WMI/cps/signsecurechannel");
RequireSecuritySignatureWs = get_kb_item("WMI/cps/RequireSecuritySignatureWs");
EnableSecuritySignatureWs = get_kb_item("WMI/cps/EnableSecuritySignatureWs");
EnablePlainTextPassword = get_kb_item("WMI/cps/EnablePlainTextPassword");
NTLMMinClientSec = get_kb_item("WMI/cps/NTLMMinClientSec");
LMCompatibilityLevel = get_kb_item("WMI/scp/LMCompatibilityLevel");
NoLMHash = get_kb_item("WMI/cps/NoLMHash");
LSAAnonymousNameLookup = get_kb_item("WMI/cps/LSAAnonymousNameLookup");
if (LSAAnonymousNameLookup != "None")
{
  LSAAnonymousNameLookup = split(LSAAnonymousNameLookup, sep:'\n', keep:0);
  LSAAnonymousNameLookup = split(LSAAnonymousNameLookup[1], sep:'|', keep:0);
  LSAAnonymousNameLookup = LSAAnonymousNameLookup[2];
}
RestrictAnonymousSAM = get_kb_item("WMI/cps/RestrictAnonymousSAM");
RestrictAnonymous = get_kb_item("WMI/cps/RestrictAnonymous");
EveryoneIncludesAnonymous = get_kb_item("WMI/cps/EveryoneIncludesAnonymous");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System läuft Samba, es ist kein Microsoft System.");
}else if("error" >< CPSGENERAL){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgeführt werden.");
}else if(( OSVER == '5.2' && OSNAME >!< 'Microsoft(R) Windows(R) XP Professional x64 Edition') || (OSVER == '6.0' && OSTYPE > 1) || (OSVER == '6.1' && OSTYPE > 1)){
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Windows-Clientbetriebssystem.");
}else if(disablepasswordchange == "0" && maximumComppasswordage >= "30" && requirestrongkey == "1" && requiresignorseal == "1" && sealsecurechannel == "1" && signsecurechannel == "1" && RequireSecuritySignatureWs == "1" && EnableSecuritySignatureWs == "1" && EnablePlainTextPassword == "0" && NTLMMinClientSec == "537395248" && LMCompatibilityLevel >= "4" && NoLMHash == "1" && LSAAnonymousNameLookup == "False" && RestrictAnonymous == "1" && RestrictAnonymousSAM == "1" && EveryoneIncludesAnonymous == "0")
{
  result = string("erfüllt");
  desc = string("Die Sicherheitseinstellungen stimmen mit der\nMaßnahme M5.123 überein.");
}else{
  result = string("nicht erfüllt");
  if (disablepasswordchange != "0") val = val + '\n' + "disablepasswordchange: " + disablepasswordchange;
  if (maximumComppasswordage < "30") val = val + '\n' + "maximumComppasswordage: " + maximumComppasswordage;
  if (requirestrongkey != "1") val = val + '\n' + "requirestrongkey: " + requirestrongkey;
  if (requiresignorseal != "1") val = val + '\n' + "requiresignorseal: " + requiresignorseal;
  if (sealsecurechannel != "1") val = val + '\n' + "sealsecurechannel: " + sealsecurechannel;
  if (signsecurechannel != "1") val = val + '\n' + "signsecurechannel: " + signsecurechannel;
  if (RequireSecuritySignatureWs != "1") val = val + '\n' + "RequireSecuritySignatureWs: " + RequireSecuritySignatureWs;
  if (EnableSecuritySignatureWs != "1") val = val + '\n' + "EnableSecuritySignatureWs: " + EnableSecuritySignatureWs;
  if (EnablePlainTextPassword != "0") val = val + '\n' + "EnablePlainTextPassword: " + EnablePlainTextPassword;
  if (NTLMMinClientSec != "537395248") val = val + '\n' + "NTLMMinClientSec: " + NTLMMinClientSec;
  if (LMCompatibilityLevel < "4") val = val + '\n' + "LMCompatibilityLevel: " + LMCompatibilityLevel;
  if (NoLMHash != "1") val = val + '\n' + "NoLMHash: " + NoLMHash;
  if (LSAAnonymousNameLookup != "False") val = val + '\n' + "LSAAnonymousNameLookup: " + LSAAnonymousNameLookup;
  if (RestrictAnonymous != "1") val = val + '\n' + "RestrictAnonymous: " + RestrictAnonymous;
  if (RestrictAnonymousSAM != "1") val = val + '\n' + "RestrictAnonymousSAM: " + RestrictAnonymousSAM;
  if (EveryoneIncludesAnonymous != "0") val = val + '\n' + "EveryoneIncludesAnonymous: " + EveryoneIncludesAnonymous;
  desc = string("Die Sicherheitseinstellungen stimmen nicht mit der Maßnahme\nM5.123 überein. Folgende Einstellungen sind nicht wie gefordert\numgesetzt:\n" + val);
}

set_kb_item(name:"GSHB/M5_123/result", value:result);
set_kb_item(name:"GSHB/M5_123/desc", value:desc);
set_kb_item(name:"GSHB/M5_123/name", value:name);


silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_123');

exit(0);

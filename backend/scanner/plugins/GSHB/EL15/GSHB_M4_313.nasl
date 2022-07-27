###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_313.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.313
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
  script_oid("1.3.6.1.4.1.25623.1.0.94232");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04313.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_PolSecSet.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_DomContrTest.nasl", "GSHB/GSHB_WMI_pre2000comp.nasl", "GSHB/GSHB_SMB_SDDL.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.313: Bereitstellung von sicheren Dom‰nen-Controllern\n';
gshbm =  "IT-Grundschutz M4.313: ";
CPSGENERAL = get_kb_item("WMI/cps/GENERAL");
OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
ClientSiteName = get_kb_item("WMI/ClientSiteName");
PreWin2000Usr = get_kb_item("WMI/PreWin2000Usr");
NtfsDisable8dot3NameCreation = get_kb_item("WMI/cps/NtfsDisable8dot3NameCreation");
rootsddl = get_kb_item("GSHB/ROOTSDDL");
log = get_kb_item("WMI/cps/GENERAL/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

if (rootsddl != "None")
{
  rootsddlres =  eregmatch(pattern:'(\\(.*\\))?(\\(.*WD\\))', string:rootsddl);
}
else rootsddlres[2] = rootsddl;


if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if("error" >< CPSGENERAL)
{
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" +log );
}else if(!CPSGENERAL){
  result = string("Fehler");
  desc = string("Beim Testen des Systems trat ein Fehler auf.\nEs konnte keine RSOP Abfrage durchgef¸hrt werden.");
}
else if((OSVER == '6.1' && OSTYPE == '2') || (OSVER == '6.0' && OSTYPE == '2') || (OSVER == '5.0' && ClientSiteName != "nodc") || (OSVER == '5.2' && ClientSiteName != "nodc"))
{
  if (NtfsDisable8dot3NameCreation == "1" && PreWin2000Usr == "None" && (rootsddlres[2] =~ "\(A;[OICNP]*;(0x00120089)?(0x001200a9)?(FR)?;;;WD\)" || !rootsddlres[2]))
  {
    result = string("erf¸llt");
    desc = string('Die Sicherheitseinstellung stimmen mit der Maﬂnahme\nM4.313 ¸berein. Bitte beachten Sie auch den Punkt\n"Neustart-Schutz mit SYSKEY" in dieser Massnahme');
  }
  else
  {
    result = string("nicht erf¸llt");
    if (NtfsDisable8dot3NameCreation != "1") val = 'NtfsDisable8dot3NameCreation ist nicht auf den\nWert -1- gesetzt.\n';
    if (PreWin2000Usr != "None") val = val + 'Der Benutzer -Jeder- befindet sich in der Gruppe Pr‰-\nWindows 2000 kompatibler Zugriff. Bitte entfernen Sie\nihn daraus.\n';
    if (!rootsddl || rootsddlres[2] == "None") val = val + 'Die Berechtigung f¸r das Root Laufwerk konnte nicht\ngelesen werden';
    else if (rootsddlres[2] !~ "\(A;[OICNP]*;(0x00120089)?(0x001200a9)?(FR)?;;;WD\)") val = val + 'Die Berechtigung f¸r das Root Laufwerk sind falsch\ngesetzt. Die Berechtigungen f¸r die Gruppe -Jeder-\nsollte auf -Lesen und Ausf¸hren- eingegrenzt werden.';

    desc = string('Die Sicherheitseinstellung stimmen nicht mit der\nMaﬂnahme M4.313 ¸berein.\n' + val + '\nBitte beachten Sie auch den Punkt\n-Neustart-Schutz mit SYSKEY- in dieser Massnahme');
  }
}
else
{
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Domaincontroller.");
}

set_kb_item(name:"GSHB/M4_313/result", value:result);
set_kb_item(name:"GSHB/M4_313/desc", value:desc);
set_kb_item(name:"GSHB/M4_313/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_313');

exit(0);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_339.nasl 12387 2018-11-16 14:06:23Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.339
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
  script_oid("1.3.6.1.4.1.25623.1.0.94243");
  script_version("$Revision: 12387 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 15:06:23 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.339: Verhindern unautorisierter Nutzung von Wechselmedien unter Windows-Clients ab Windows Vista");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04339.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_WMI_CD-Autostart.nasl", "GSHB/GSHB_WMI_Driver-Autostart.nasl", "GSHB/GSHB_WMI_CD-FD-User-only-access.nasl", "GSHB/GSHB_WMI_AllowRemoteDASD.nasl");
  script_require_keys("WMI/AllowRemoteDASD");

  script_tag(name:"summary", value:"IT-Grundschutz M4.339: Verhindern unautorisierter Nutzung von Wechselmedien unter Windows-Clients ab Windows Vista.

  Stand: 15. Erg‰nzungslieferung (15. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.339: Verhindern unautorisierter Nutzung von Wechselmedien unter Windows-Clients ab Windows Vista\n';

OSVER = get_kb_item("WMI/WMI_OSVER");
OSTYPE = get_kb_item("WMI/WMI_OSTYPE");
cdauto = get_kb_item("WMI/CD_Autostart");
cdalloc = get_kb_item("WMI/CD_Allocated");
fdalloc = get_kb_item("WMI/FD_Allocated");
AllowRemoteDASD = get_kb_item("WMI/AllowRemoteDASD");
AllowRemoteDASD = get_kb_item("WMI/AllowRemoteDASD/log");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
driverauto = get_kb_item("WMI/Driver_Autoinstall");
allowAdminInstall = get_kb_item("WMI/AllowAdminInstall");
gshbm = "GSHB Maﬂnahme 4.339: ";

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba,\nes ist kein Microsoft Windows System.");
}else if(AllowRemoteDASD == "error"){
  result = string("Fehler");
  if (!log)desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log)desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(OSVER  >=  "6.0" && OSTYPE == "1"){
  if(cdauto >< "on" || cdalloc >< "off" || fdalloc >< "off" || AllowRemoteDASD != "0" || driverauto != "off" || allowAdminInstall >< "on")
  {
    result = string("nicht erf¸llt");
    if(cdauto >< "on") desc = string('CD-Autostart ist nicht deaktiviert!\n');
    if(cdalloc >< "off") desc += string('CD-Zugriff ist weiterhin ¸ber Netzwerk mˆglich!\n');
    if(fdalloc >< "off") desc += string('FD-Zugriff ist weiterhin ¸ber Netzwerk mˆglich!\n');
    if(AllowRemoteDASD != "0") desc += string('Direkter Zugriff auf Wechselmedien in Remotesitzungen\nist weiterhin mˆglich.\n');
    if(driverauto !=  "off" ) desc += string('Die automatische Installation von Treibern ist mˆglich.\n');
    if(allowAdminInstall >< "on") desc += string('Administratoren kˆnnen keine Treiber unabh‰ngig\nder Gruppenrichtlinie installieren oder aktualisieren.\n');
  } else if(cdauto >< "off" && cdalloc >< "on" && fdalloc >< "on" && AllowRemoteDASD == "0" || driverauto == "off" || allowAdminInstall == "on")
  {
    result = string("erf¸llt");
    desc = string("Das System entspricht der IT-Grundschutz Maﬂnahme\nM4.339.");
  }
}else{
  result = string("nicht zutreffend");
  desc = string("Das System ist kein Microsoft Windows System grˆﬂer gleich Windows Vista.");
}

set_kb_item(name:"GSHB/M4_339/result", value:result);
set_kb_item(name:"GSHB/M4_339/desc", value:desc);
set_kb_item(name:"GSHB/M4_339/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_339');

exit(0);

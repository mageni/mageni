###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_020.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.020
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
  script_oid("1.3.6.1.4.1.25623.1.0.94188");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04020.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_SSH_umask.nasl", "GSHB/GSHB_SSH_setuid.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.020: Restriktive Attributvergabe bei Unix-Benutzerdateien und -verzeichnissen\n';

gshbm =  "IT-Grundschutz M4.020: ";

umask = get_kb_item("GSHB/umask");
umasklog = get_kb_item("GSHB/umask/log");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");
setuid = get_kb_item("GSHB/setuid/home");
setuidlog = get_kb_item("GSHB/setuid/log");
tempsticky = get_kb_item("GSHB/tempsticky");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(umask >< "error"){
  result = string("Fehler");
  if (!umasklog)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (umasklog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + umasklog);
}else if(umask == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(umask >< "none" && setuid >< "none" && (tempsticky == "true" || tempsticky == "notmp" )){
  result = string("erf¸llt");
  desc = string('Es konnten keine fehlerhaften umask-Eintr‰ge und\nDateien mit setuid-Bit unter /home/* gefunden werden.');
}else if(umask >!< "none" || setuid >!< "none" || tempsticky == "false"){
  result = string("nicht erf¸llt");
  if(umask >!< "none") desc = string('Folgende fehlerhaften umask-Eintr‰ge wurden gefunden:\n' + umask);
  if(setuid >!< "none") desc += string('Folgende Dateien mit setuid-Bit wurden gefunden:\n' + setuid);
  if(tempsticky == "false") desc += string('F¸r das Verzeichnis /tmp wurde das sticky-Bit\nnicht gesetzt.');
}

set_kb_item(name:"GSHB/M4_020/result", value:result);
set_kb_item(name:"GSHB/M4_020/desc", value:desc);
set_kb_item(name:"GSHB/M4_020/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_020');

exit(0);

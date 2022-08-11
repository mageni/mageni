###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_005.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.005
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
  script_oid("1.3.6.1.4.1.25623.1.0.94176");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.005: Protokollierung bei TK-Anlagen");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04005.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_list_Services.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_syslog.nasl");
  script_require_keys("WMI/EventLogService");
  script_tag(name:"summary", value:"IT-Grundschutz M4.005: Protokollierung bei TK-Anlagen

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.005: Protokollierung der TK-Administrationsarbeiten\n';

gshbm =  "IT-Grundschutz M4.005: ";
OSVER = get_kb_item("WMI/WMI_OSVER");
OSNAME = get_kb_item("WMI/WMI_OSNAME");
eventlog = get_kb_item("WMI/EventLogService");
log = get_kb_item("WMI/EventLogService/log");

syslog = get_kb_item("GSHB/syslog");
rsyslog = get_kb_item("GSHB/rsyslog");
log_rsyslog = get_kb_item("GSHB/rsyslog/log");

if(OSVER >!< "none"){
  if (eventlog >!< "None" || eventlog >!< "error") eventlog = split(eventlog, sep:"|", keep:0);

  if("error" >< eventlog){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if("None" >< eventlog){
    result = string("nicht erf¸llt");
    desc = string("Auf dem System wurde kein Eventlog gefunden.");
  }else if("Running" >< eventlog[2]){
    result = string("unvollst‰ndig");
    desc = string("Eventlog l‰uft auf dem System. Bitte pr¸fen Sie ob\nIhre TK-Anlage das Eventlog zum Abspeichern der Events\nbenutzt.");
  }else if("Stopped" >< eventlog[2]){
    result = string("nicht erf¸llt");
    desc = string("Eventlog l‰uft auf dem System nicht. Starten Sie\nEventlog und pr¸fen Sie ob Ihre TK-Anlage das Eventlog\nzum Abspeichern der Events benutzt.");
  }
}else{
  if(syslog == "windows") {
    result = string("Fehler");
    if (OSNAME >!< "none" && OSNAME >!< "error") desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nAllerdings konnte auf das System nicht korrekt zuge-\ngriffen werden. Folgende Fehler sind aufgetreten:\n' + log);
    else desc = string('Das System scheint ein Windows-System zu sein.\nAllerdings konnte auf das System nicht korrekt\nzugegriffen werden. Folgende Fehler sind aufgetreten:\n' + log);
  }else if("error" >< syslog){
    result = string("Fehler");
    if (!log_rsyslog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log_rsyslog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if("off" >< syslog && "off" >< rsyslog){
    result = string("nicht erf¸llt");
    desc = string("Auf dem System l‰uft weder syslog noch rsyslog, um\nggf. Events aus der TK-Anlage zu speichern.");
  }else{
    result = string("unvollst‰ndig");
    desc = string("Syslog/Rsyslog l‰uft auf dem System. Bitte pr¸fen Sie\nob Ihre TK-Anlage Syslog/Rsyslog zum Abspeichern der\nEvents benutzt.");
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_005/result", value:result);
set_kb_item(name:"GSHB/M4_005/desc", value:desc);
set_kb_item(name:"GSHB/M4_005/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_005');

exit(0);

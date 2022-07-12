###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_040.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.040
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
  script_oid("1.3.6.1.4.1.25623.1.0.94203");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04040.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_audio.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras

  Stand: 14. Erg‰nzungslieferung (14. EL).

  Hinweis:

  Nur f¸r Linux umgesetzt. Es ist unter Windows nicht mˆglich den Status des Mikrofons ¸ber Registry/WMI auszulesen.");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.040: Verhinderung der unautorisierten Nutzung von Rechnermikrofonen und Kameras\n';

gshbm =  "IT-Grundschutz M4.040: ";
OSNAME = get_kb_item("WMI/WMI_OSNAME");
package = get_kb_item("GSHB/AUDIO/package");
devaudio = get_kb_item("GSHB/AUDIO/devaudio");
log = get_kb_item("GSHB/AUDIO/log");

syslog = get_kb_item("GSHB/syslog");
rsyslog = get_kb_item("GSHB/rsyslog");
log_rsyslog = get_kb_item("GSHB/rsyslog/log");

if(OSNAME >!< "none"){
  result = string("unvollst‰ndig");
  desc = string('Es ist unter Windows nicht mˆglich, den Status des\nMikrofons ¸ber Registry/WMI auszulesen.');
}
else if(devaudio != "windows") {
    if("error" >< devaudio){
    result = string("Fehler");
    if (!log_rsyslog) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log_rsyslog) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else if (devaudio == "no audio"){
    result = string("erf¸llt");
    desc = string('In Ihrem System konnte keine Audio-Komponenten\nermittelt werden um ein Microfone anzuschlieﬂen.');
  }else if (devaudio =~ ".......---.*root.audio.*" && package == "none"){
    result = string("erf¸llt");
    desc = string('Der zugriff auf /dev/audio ist auf root beschr‰nkt und\nes wurde keine der folgenden Audio-Server Pakete\ngefunden: esound, paudio, pulseaudio, artsd, phonon');
  }else if (devaudio !~ ".......---.*root.audio.*" || package != "none") {
    result = string("nicht erf¸llt");
    if (devaudio !~ ".......---.*root.audio.*")desc = string('Sie sollten den Zugriff auf /dev/audio\nauf root beschr‰nken. ');
    if (package != "none")desc += string('Folgende Audioserver Pakete wurden auf dem\nSystem gefunden:\n' + package);
  }
}
else{
  result = string("Fehler");
  desc = string('Beim Testen des Systems konnte dies nicht korrekt\nerkannt werden.\nSollte es sich um ein Windows-System\nhandeln, ist es nicht mˆglich den Status des Mikrofons\n¸ber Registry/WMI auszulesen.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_040/result", value:result);
set_kb_item(name:"GSHB/M4_040/desc", value:desc);
set_kb_item(name:"GSHB/M4_040/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_040');

exit(0);

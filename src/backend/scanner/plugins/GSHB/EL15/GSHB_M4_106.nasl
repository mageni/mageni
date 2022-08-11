###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_106.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.106
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
  script_oid("1.3.6.1.4.1.25623.1.0.94214");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04106.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_syslog.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.106: Aktivieren der Systemprotokollierung\n';

gshbm =  "IT-Grundschutz M4.106: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");
var_log = get_kb_item("GSHB/var_log");
var_adm = get_kb_item("GSHB/var_adm");
syslog = get_kb_item("GSHB/syslog");
rsyslog = get_kb_item("GSHB/rsyslog");
syslogr = get_kb_item("GSHB/syslogr");
rsyslogr = get_kb_item("GSHB/rsyslogr");
log = get_kb_item("GSHB/rsyslog/log");


if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(rsyslog == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(rsyslog >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein\nunbekannter Fehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if((var_log =~ "d......r...*" || var_adm =~ "d......r...*") || (syslogr =~ "........w..*" || rsyslogr =~ "........w..*")){
  result = string("nicht erf¸llt");
  if (var_log =~ "d......r...*" && var_adm =~ "d......r...*") desc = string('F¸r die Verzeichnisse /var/log und /var/adm sind\nˆffentliche Leserechte eingestellt, bitte ‰ndern Sie\ndas:' + '\n/var/log: ' + var_log + '\n/var/adm: ' + var_adm);
  else if (var_log =~ "d......r...*") desc = string('F¸r das Verzeichnis /var/log sind ˆffentliche\nLeserechte eingestellt, bitte ‰ndern Sie das:\n/var/log: ' + var_log);
  else if (var_adm =~ "d......r...*") desc = string('F¸r das Verzeichnis /var/adm sind ˆffentliche\nLeserechte eingestellt, bitte ‰ndern Sie das:\n/var/adm: '  + var_adm);
  if (syslogr =~ "........w..*" || rsyslogr =~ "........w..*")desc += string('\nF¸r die Dateien /etc/syslog.conf und /etc/rsyslog.conf\nsind ˆffentliche Schreibrechte eingestellt, bitte\n‰ndern Sie das:\n/etc/syslog.conf: ' + syslogr + '\n/etc/rsyslog.conf: ' + rsyslogr);
  else if (syslogr =~ "........w..*") desc += string('\nF¸r die Datei /etc/syslog.conf sind ˆffentliche\nSchreibrechte eingestellt, bitte ‰ndern Sie das:\n/etc/syslog.conf: ' + syslogr);
  else if (rsyslogr =~ "........w..*") desc += string('\nF¸r die Datei /etc/rsyslog.conf sind ˆffentliche\nSchreibrechte eingestellt, bitte ‰ndern Sie das:\n/etc/rsyslog.conf: ' + rsyslogr);
}else if((syslog == "none" && rsyslog == "norights") || (rsyslog == "none" && syslog == "norights") || (syslog == "norights" && rsyslog == "norights")){
  result = string("unvollst‰ndig");
  if(syslog == "norights" && rsyslog == "norights") desc = string('Sie haben kein Berechtigung die Dateien\n/etc/syslog.conf und /etc/rsyslog.conf zu lesen.');
  else if(rsyslog == "norights") desc = string('Sie haben kein Berechtigung die Datei\n/etc/rsyslog.conf zu lesen.');
  else if(syslog == "norights") desc = string('Sie haben kein Berechtigung die Datei\n/etc/syslog.conf zu lesen.');
}else if((syslog == "none" && syslog == "off" ) && (rsyslog == "none" && rsyslog == "off")){
  result = string("Fehler");
  desc = string('Die Dateien /etc/syslog.conf und /etc/rsyslog.conf\nwurden nicht gefunden.');
}else{
  result = string("unvollst‰ndig");
  desc = string('Die Berechtigungen f¸r /etc/var, /etc/log,\n/etc/syslog.conf bzw. /etc/rsyslog.conf sind korrekt\ngesetzt.\nBitte pr¸fen Sie ob unten angegebenen\nParameter aus');
  if (syslog != "none" && syslog != "off") {
    Lst = split(syslog, keep:0);
    for (i=0; i<max_index(Lst); i++){
      if (Lst[i] == "") continue;
      parameter += Lst[i] + '\n';
    }
    desc += string(' der Datei /etc/syslog.conf,\ndenen der Maﬂnahme 4.106 entsprechen.\n' + parameter);
  }
  else if (rsyslog != "none" && rsyslog != "off") {
    Lst = split(rsyslog, keep:0);
    for (i=0; i<max_index(Lst); i++){
      if (Lst[i] == "") continue;
      parameter += Lst[i] + '\n';
    }
    desc += string(' der Datei /etc/rsyslog.conf,\ndenen der Maﬂnahme 4.106 entsprechen.\n' + parameter);
  }
}
if (!result){
  result = string("Fehler");
  desc = string(' Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_106/result", value:result);
set_kb_item(name:"GSHB/M4_106/desc", value:desc);
set_kb_item(name:"GSHB/M4_106/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_106');

exit(0);

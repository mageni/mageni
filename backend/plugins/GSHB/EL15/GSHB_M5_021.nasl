###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_021.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.021
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
  script_oid("1.3.6.1.4.1.25623.1.0.95058");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05021.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_SSH_r-tools.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_TFTP_s-option.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.021: Sicherer Einsatz von telnet, ftp, tftp und rexec\n';

gshbm =  "IT-Grundschutz M5.021: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

inetdconf = get_kb_item("GSHB/R-TOOL/inetdconf");
ftpusers = get_kb_item("GSHB/R-TOOL/ftpusers");
netrc = get_kb_item("GSHB/R-TOOL/netrc");
log = get_kb_item("GSHB/R-TOOL/log");
tftp = get_kb_item("GSHB/TFTP/s-option");

if (inetdconf >!< "noentry" && inetdconf >!< "none"){
  Lst = split(inetdconf, keep:0);
  for(i=0; i<max_index(Lst); i++){
    if (Lst[i] =~ "^ftp.*") val_ftp = "yes";
    if (Lst[i] =~ "^tftp.*") val_tftp = "yes";
    if (Lst[i] =~ "^telnet.*") val_telnet = "yes";
  }
}

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(inetdconf == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(inetdconf == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if (netrc != "not found" || val_tftp == "yes" || tftp == "fail" || val_telnet == "yes" || (val_ftp == "yes" && ftpusers == "noentry")){
  result = string("nicht erf¸llt");
  if (netrc != "not found")desc = string('Es muss sichergestellt werden, dass keine .netrc-Dateien in den\nBenutzerverzeichnissen vorhanden sind oder dass sie leer sind\nund der Benutzer keine Zugriffsrechte auf diese hat. Folgende\n.netrc-Dateien wurden gefunden:\n' + netrc);
  if (val_tftp == "yes") desc += string('\nDer Einsatz des Daemons tftpd muss verhindert werden (z. B.\ndurch Entfernen\ndes entsprechenden Eintrags in der Datei\n/etc/inetd.conf).');
  if (val_ftp == "yes") desc += string('\nF¸hren Sie bitte einen NVT-Scan aus, um mˆgliche Sicherheits-\nl¸cken im installierten FTP-Server zu finden.');
  if (val_ftp == "yes" && ftpusers == "noentry")desc += string('Es konnten keine Eintr‰ge in der Datei -/etc/ftpusers- gefunden\nwerden. In die Datei /etc/ftpusers sollten alle Benutzernamen\neingetragen werden, f¸r die ein ftp-Zugang nicht erlaubt werden\nsoll. Hierzu gehˆren z. B. root, uucp und bin.');
  if (val_ftp == "yes" && ftpusers != "none")desc += string('\nIn die Datei /etc/ftpusers sollten alle Benutzernamen\neingetragen werden, f¸r die ein\nftp-Zugang nicht erlaubt\nwerden soll. Hierzu gehˆren z. B. root, uucp und bin. Folgende\nEintr‰ge wurden in der Datei -/etc/ftpusers- gefunden: \n' + ftpusers);
  if (val_telnet == "yes") desc += string('\nAuf dem Zilesystem wurde ein Telnet-Server in der\n-/etc/inetd.conf- gefunden. Sie sollten SSH anstelle von\ntelnet nutzen.');
  if (tftp == "fail") desc += string('Es muss sichergestellt sein, dass beim Einsatz von tftp den\nBenutzern aus dem Login-Verzeichnis nur eingeschr‰nkte\nDateizugriffe mˆglich sind. In diesem Fall war es mˆglich auf\ndie Datei -/etc/passwd- zuzugreifen. Starten Sie den\ntftp-Daemon mit der Option -s verzeichnis.');
}else{
  result = string("erf¸llt");
  desc = string("Das System entspricht der Maﬂnahme 5.021.");
  if (val_ftp == "yes") desc += string('\nF¸hren Sie bitte einen NVT-Scan aus, um mˆgliche\nSicherheitsl¸cken im installierten FTP-Server zu finden.');
  if (val_ftp == "yes" && ftpusers != "none")desc += string('\n\nIn die Datei /etc/ftpusers sollten alle Benutzernamen\neingetragen werden, f¸r die ein ftp-Zugang nicht erlaubt werden\nsoll. Hierzu gehˆren z. B. root, uucp und bin. Folgende\nEintr‰ge wurden in der Datei -/etc/ftpusers- gefunden: \n' + ftpusers);
}


if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M5_021/result", value:result);
set_kb_item(name:"GSHB/M5_021/desc", value:desc);
set_kb_item(name:"GSHB/M5_021/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_021');

exit(0);

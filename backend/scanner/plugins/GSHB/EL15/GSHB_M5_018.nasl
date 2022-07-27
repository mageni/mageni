###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_018.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maßnahme 5.018
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
  script_oid("1.3.6.1.4.1.25623.1.0.95054");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05018.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_NIS.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS.

  Stand: 14. Ergänzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.018: Einsatz der Sicherheitsmechanismen von NIS\n';

gshbm =  "IT-Grundschutz M5.018: ";

OSNAME = get_kb_item("WMI/WMI_OSNAME");

server = get_kb_item("GSHB/NIS/server");
client = get_kb_item("GSHB/NIS/client");
ypbind = get_kb_item("GSHB/NIS/ypbind");
ypserv = get_kb_item("GSHB/NIS/ypserv");
NisPlusUserwopw = get_kb_item("GSHB/NIS/NisPlusUserwopw");
NisPlusGenUserwopw = get_kb_item("GSHB/NIS/NisPlusGenUserwopw");
NisPlusUserwpw = get_kb_item("GSHB/NIS/NisPlusUserwpw");
NisPlusGenUserwpw = get_kb_item("GSHB/NIS/NisPlusGenUserwpw");
LocalUID0 = get_kb_item("GSHB/NIS/LocalUID0");
NisPlusGroupwopw = get_kb_item("GSHB/NIS/NisPlusGroupwopw");
NisPlusGenGroupwopw = get_kb_item("GSHB/NIS/NisPlusGenGroupwopw");
NisPlusGroupwpw = get_kb_item("GSHB/NIS/NisPlusGroupwpw");
NisPlusGenGroupwpw = get_kb_item("GSHB/NIS/NisPlusGenGroupwpw");
hostsdeny = get_kb_item("GSHB/NIS/hostsdeny");
hostsallow = get_kb_item("GSHB/NIS/hostsallow");
securenets = get_kb_item("GSHB/NIS/securenets");
log = get_kb_item("GSHB/NIS/log");

if ((server == "windows" && client == "windows") || (server == "error" && client == "error" && OSNAME != "none")){
    result = string("nicht zutreffend");
    if (OSNAME == "none") desc = string('Auf dem System läuft kein NIS (Network Information Service.');
    else desc = string('Auf dem System läuft kein NIS (Network Information Service),\nda es sich um ein\n' + OSNAME + '\nSystem handelt.');
}else if(server == "no" && client == "no" && ypbind == "no" && ypserv == "no" || ((client == "yes" && ypbind == "no") && (server == "yes" && ypserv == "no") ) ){

  if (NisPlusUserwopw == "yes" || NisPlusGenUserwopw == "yes" || NisPlusGenGroupwopw == "yes" || NisPlusGroupwopw == "yes" ){
    result = string("nicht erfüllt");
    desc = string('Auf dem System läuft kein NIS (Network Information Service).\nAllerdings wurden NIS Einträge in Ihrer\n');
    if ((NisPlusUserwopw == "yes" || NisPlusGenUserwopw == "yes") && NisPlusGenGroupwopw == "no" && NisPlusGroupwopw == "no") desc += string(' -/etc/passwd- Datei gefunden.');
    else if (NisPlusUserwopw == "no" && NisPlusGenUserwpw == "no" && (NisPlusGenGroupwopw == "yes" || NisPlusGroupwopw == "yes")) desc += string(' -/etc/group- Datei gefunden.');
    else if (NisPlusUserwopw == "yes" && NisPlusGenUserwopw == "yes" && NisPlusGenGroupwopw == "yes" && NisPlusGroupwopw == "yes") desc += string(' -/etc/passwd- und -/etc/group- Datei gefunden.');
  }else {
    result = string("nicht zutreffend");
    desc = string('Auf dem System läuft kein NIS (Network Information Service).');
  }
}else if(server == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if((server == "yes" &&  ypserv == "yes") || (client == "yes" && ypbind == "yes")){
  if (server == "yes" &&  ypserv == "yes"){
    if (NisPlusUserwopw == "yes" || NisPlusGroupwopw == "yes" || ((securenets == "everybody" || securenets == "none") && (hostsdeny == "noentry" || hostsallow == "noentry"))){
      result = string("nicht erfüllt");
      if (NisPlusUserwopw == "yes") desc += string('\nIn der Passwortdatei -/etc/passwd- darf der Eintrag +::0:0:::\nnicht enthalten sein, da sonst ein Zugang mit dem Namen + ohne\nPasswort existiert.\nSollte der Eintrag notwendig sein, muss\ndas Passwort durch ein "*" ersetzt werden.');
      if (NisPlusGroupwopw == "yes") desc += string('\nIn der Gruppendatei -/etc/group- darf der Eintrag +::0: nicht\nenthalten sein,\nda sonst ein Zugang mit dem Namen + ohne\nPasswort existiert.\nSollte der Eintrag notwendig sein, muss\ndas Passwort durch ein "*" ersetzt werden.');
      if (securenets == "everybody" && (hostsdeny == "noentry" && hostsallow == "noentry"))desc += string('\nDer Server-Prozess ypserv sollte nur Anfragen von vorher fest-\ngelegten Rechnern beantworten.\nSie sollten Dazu die speziellen\nKonfigurationsdatei namens /etc/ypserv.securenet oder die\nDateien /etc/hosts.allow und /etc/hosts.deny bearbeiten.');
      else if ((securenets == "everybody" || securenets == "none") && (hostsallow != "noentry" && hostsdeny != "noentry")) desc += string('\nDer Server-Prozess ypserv sollte nur Anfragen von vorher fest-\ngelegten Rechnern beantworten. Sie sollten Dazu die speziellen\nKonfigurationsdatei namens /etc/ypserv.securenet bearbeiten.');
      else{
        if (hostsallow == "noentry" || hostsdeny == "noentry")desc += string('\nDer Server-Prozess ypserv sollte nur Anfragen von vorher fest-\ngelegten Rechnern beantworten.');
        if (hostsallow == "noentry" && hostsdeny != "noentry")desc += string('\nSie sollten Dazu die Datei /etc/hosts.allow bearbeiten. In der\nDatei /etc/hosts.deny wurde schon ein Eintrag gefunden:\n' + hostsdeny);
        else if (hostsdeny == "noentry" && hostsallow != "noentry")desc += string('\nSie sollten Dazu die Datei /etc/hosts.deny bearbeiten. In der\nDatei /etc/hosts.allow wurde schon ein Eintrag gefunden:\n' + hostsallow);
        else if (hostsallow == "noentry" && hostsdeny == "noentry") desc += string('\nSie sollten Dazu die Dateien /etc/hosts.allow und\n/etc/hosts.deny bearbeiten.');
      }
    }else{
      result = string("erfüllt");
      desc = string('Die Einstellungen für Ihren  NIS (Network Information Service)\nServer, entspechen den Empfehlungen der Maßnahme 5.018.');
    }
  }
  if (client == "yes" && ypbind == "yes" && (server == "no" || ypserv == "no")){
    if(NisPlusGenUserwopw == "yes" || NisPlusGenGroupwopw == "yes" || NisPlusUserwopw == "yes" || NisPlusGroupwopw == "yes" || LocalUID0 == "no" || LocalUID0 == "not first"){
      result = string("nicht erfüllt");

      if (NisPlusUserwopw == "yes") desc += string('\nIn Ihrer Passwortdatei /etc/passwd wurde der Eintrag\n+::0:0::: gefunden.');
      if (NisPlusGroupwopw == "yes") desc += string('\nIn Ihrer Gruppendatei /etc/group wurde der Eintrag\n+::0: gefunden.');
      if (NisPlusGenUserwopw == "yes") desc += string('\nIn Ihrer Passwortdatei /etc/passwd wurde der Eintrag\n+:::::: gefunden.');
      if (NisPlusGenGroupwopw == "yes") desc += string('\nIn Ihrer Gruppendatei /etc/group wurde der Eintrag\n+::: gefunden.');
      if (NisPlusUserwopw == "yes" || NisPlusGroupwopw == "yes" || NisPlusGenUserwopw == "yes" || NisPlusGenGroupwopw == "yes")desc += string('\n\nEs muss auf jeden Fall ein Eintrag im Passwortfeld vorhanden\nsein, damit nicht im Falle einer (beabsichtigten oder nicht\nbeabsichtigten) Nichtbenutzung von NIS\nversehentlich ein\nZugang mit dem Benutzernamen + ohne Passwort geschaffen wird.');
      if (LocalUID0 == "no" || LocalUID0 == "not first") desc += string('\nUm zu verhindern, dass der NIS-Administrator auf allen NIS-\nClients root-Rechte hat, sollte auf jedem NIS-Client ein\nlokaler Benutzer mit der UID 0 eingerichtet werden.');
      if (LocalUID0 == "no") desc += string('\nAuf Ihrem System wurde kein solcher User gefunden.');
      else if (LocalUID0 == "not first") desc += string('\nAuf Ihrem System wurde zwar ein solcher User gefunden, dieser\nsollte aber vor dem -NIS User- mit der UID 0 stehen.');
    }else{
      result = string("erfüllt");
      desc = string('Die Einstellungen für Ihren  NIS (Network Information Service)\nClient, entspechen den Empfehlungen der Maßnahme 5.018.');
      if (NisPlusUserwpw == "yes" || NisPlusGenUserwpw == "yes" ) desc += string('\nDer Eintrag +:*:0:0::: bzw. +:*::::: in der Passwortdatei\n/etc/passwd sollte dokumentiert werden.');
      if (NisPlusGroupwpw == "yes" || NisPlusGenGroupwpw == "yes") desc += string('\nDer Eintrag +:*:0 bzw. +:*: in der Passwortdatei /etc/passwd\nsollte dokumentiert werden.');
    }
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M5_018/result", value:result);
set_kb_item(name:"GSHB/M5_018/desc", value:desc);
set_kb_item(name:"GSHB/M5_018/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_018');

exit(0);

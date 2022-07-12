###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_019.nasl 13075 2019-01-15 09:32:16Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.019
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
  script_oid("1.3.6.1.4.1.25623.1.0.95056");
  script_version("$Revision: 13075 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-15 10:32:16 +0100 (Tue, 15 Jan 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.019: Einsatz der Sicherheitsmechanismen von sendmail");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05019.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("GSHB/GSHB_SMTP_sendmail.nasl", "GSHB/GSHB_SSH_sendmail.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_tag(name:"summary", value:"IT-Grundschutz M5.019: Einsatz der Sicherheitsmechanismen von sendmail.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.019: Einsatz der Sicherheitsmechanismen von sendmail\n';

gshbm =  "IT-Grundschutz M5.019: ";

DEBUG = get_kb_item("GSHB/SENDMAIL/DEBUG");
VRFX = get_kb_item("GSHB/SENDMAIL/VRFX");
EXPN = get_kb_item("GSHB/SENDMAIL/EXPN");
LSMAILCNF = get_kb_item("GSHB/SENDMAIL/LSMAILCNF");
lssendmailcnfdir = get_kb_item("GSHB/SENDMAIL/lssendmailcnfdir");
sendmailcnf = get_kb_item("GSHB/SENDMAIL/sendmailcnf");
mlocalp = get_kb_item("GSHB/SENDMAIL/mlocalp");
lsmlocalp = get_kb_item("GSHB/SENDMAIL/lsmlocalp");
lsstatusfiledir = get_kb_item("GSHB/SENDMAIL/lsstatusfiledir");
lsstatusfile = get_kb_item("GSHB/SENDMAIL/lsstatusfile");
statusfile = get_kb_item("GSHB/SENDMAIL/statusfile");
statusfiledir = get_kb_item("GSHB/SENDMAIL/statusfiledir");
fx = get_kb_item("GSHB/SENDMAIL/fx");
mlocal = get_kb_item("GSHB/SENDMAIL/mlocal");
lsforward = get_kb_item("GSHB/SENDMAIL/lsforward");
queuedir = get_kb_item("GSHB/SENDMAIL/queuedir");
lsqueuedir = get_kb_item("GSHB/SENDMAIL/lsqueuedir");
lsqueue = get_kb_item("GSHB/SENDMAIL/lsqueue");
aliases = get_kb_item("GSHB/SENDMAIL/aliases");
aliaspath = get_kb_item("GSHB/SENDMAIL/aliaspath");
incaliases = get_kb_item("GSHB/SENDMAIL/incaliases");
lsaliases = get_kb_item("GSHB/SENDMAIL/lsaliases");
lsaliasesdb = get_kb_item("GSHB/SENDMAIL/lsaliasesdb");

sendmailfunc = get_kb_item("GSHB/SENDMAIL");
log = get_kb_item("GSHB/SENDMAIL/log");

sendmail = get_kb_item("sendmail/detected");

if (!sendmail){
  result = string("nicht zutreffend");
  desc = string("Auf dem System konnte Sendmail nicht entdeckt werden.");
}else if(DEBUG == "error" || EXPN == "error" || VRFX == "error"){
  result = string("Fehler");
  desc = string('Beim Abfragen des Sendmail-Servers konnte kein Ergebnis\nermittelt werden.');
}else if(DEBUG == "nosoc" || EXPN == "nosoc" || VRFX == "nosoc"){
  result = string("Fehler");
  desc = string('Es konnte keine Verbindung mit dem SMTP Server\naufgenommen werden..');
}else if(sendmailfunc == "error"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}
else{
  if (DEBUG == "yes"){
    valcheck += "FAIL";
    desc = string('Der sendmail-Prozess wird im Debug-Modus betrieben.\n');
  }
  if (EXPN == "yes"){
    valcheck += "FAIL";
    desc += string('Der Befehl -expn- ist verf¸gbar. Bei Version >= 8 von sendmail\nl‰sst sich der Befehle z. B. durch die Option p (privacy)\nbeim Starten abschalten.\n');
  }
  if (VRFX == "yes"){
    valcheck += "FAIL";
    desc += string('Der Befehl -vrfx- ist verf¸gbar. Bei Version >= 8 von sendmail\nl‰sst sich der Befehle z. B. durch die Option p (privacy)\nbeim Starten abschalten.\n');
  }
  if (LSMAILCNF >!< "none"){
    if (LSMAILCNF !~ "-rw.r..--- . root root.*"){
      valcheck += "FAIL";
      desc += string('Die Datei -/etc/mail/sendmail.cf- hat nicht die in der Maﬂnahme\n5.019 geforderten Berechtigungen.\n' + LSMAILCNF + '\n');
    }
    else valcheck += "OK";
    if (lssendmailcnfdir !~ "d......--- . root root.*"){
      valcheck += "FAIL";
      desc += string('Der Ordner -/etc/mail- hat nicht die in der Maﬂnahme 5.019\ngeforderten Berechtigungen.\n' + lssendmailcnfdir + '\n');
    }
    else valcheck += "OK";
    if (fx =="none")valcheck += "OK";
    else if (fx =~ "FX|.*"){
      valcheck += "FAIL";
      desc += string('Die Programmform des F-Kommandos(z. B. FX|/tmp/prg) sollte\nnicht benutzt werden!.\n' + fx + '\n');
    }

    if (lsstatusfile != "none" && lsstatusfile != "nofile" && lsstatusfile !~ "-......--- . root root.*"){
      valcheck += "FAIL";
      desc += string('Die Datei -' + statusfile +'- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n' + lsstatusfile + '\n');
    }
    else valcheck += "OK";
    if (lsstatusfiledir !~ "d......--- . root root.*"){
      valcheck += "FAIL";
      statusfiledir = ereg_replace(string:statusfiledir, pattern:'\n', replace:"", icase:0);
      desc += string('Der Ordner -' + statusfiledir + '- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n' + lsstatusfiledir + '\n');
    }
    else valcheck += "OK";

    if (lsaliases  !~ "-......--- . root root.*"){
      valcheck += "FAIL";
      aliaspath = ereg_replace(string:aliaspath, pattern:'\n', replace:"", icase:0);
      desc += string('Die Datei -' + aliaspath + '- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n' + lsaliases + '\n');
    }
    else valcheck += "OK";
    if (lsaliasesdb  !~ "-......--- . root root.*"){
      valcheck += "FAIL";
      desc += string('Die Datei -' + aliaspath + '.db- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n' + lsaliasesdb + '\n');
    }
    else valcheck += "OK";
    if (aliases != "none"){
      Lst = split(aliases, keep:0);
      for (i=0; i<Lst; i++){
        if (Lst[i] =~ ".*:.*/.*/.*") aliasval += "fail";
      }
      if ("fail" >< aliasval){
        valcheck += "FAIL";
        desc += string('Aus der Alias-Datei sollte jedes ausf¸hrbare Programm\nentfernt werden.');
      }
      else valcheck += "OK";
    }
    if (lsqueuedir !~ "drwx...... . root root.*"){
      valcheck += "FAIL";
      queuedir = ereg_replace(string:queuedir, pattern:'\n', replace:"", icase:0);
      desc += string('Der Ordner -' + queuedir + '- hat nicht die in der\nMaﬂnahme 5.019 geforderten Berechtigungen.\n' + lsqueuedir + '\n');
    }
    if (lsforward == "none" && lsforward == "not found") valcheck += "OK";
    else{
      Lst = split(lsforward, keep:0);
      for (i=0; i<Lst; i++){
        if (Lst[i] =~"......... . .* .* .* ..-..-.. .* .*/root/.*"  || Lst[i] =~"......... . .* .* .* ..-..-.. .* .*/bin/.*"){
          valcheck += "FAIL";
          lsforwardcheck += Lst[i] + '\n';
        }
      if (lsforwardcheck) desc += string('Privilegierte Benutzer wie bin oder root sollten keine .forward\nDatei besitzen.\n' + lsforwardcheck + '\n');
      desc += string('F¸r normale Benutzer sollte die .forward-Datei nur von dem\nBesitzer beschreibbar sein und muss sich in einem Verzeichnis\nbefinden, das dem Besitzer gehˆrt. Bitte Pr¸fen Sie folgende\nErgebnisse:\n' + lsforward + '\n');
      }
    }
    if (mlocalp != "none"){
      mlocalp = split(mlocalp, sep:"=", keep:0);
#      mlocalp = malocalp[1];
      valcheck += "DISPLAY";
      desc += string('Bei der Definition des Delivery Agents (z. B. Mlocal) d¸rfen\nnur absolute Pfade angegeben werden (z. B. P=/bin/mail).\nPr¸fen Sie von daher folgenden Eintrag:\n' + mlocalp[1] + '\n');
    }
    if (lsmlocalp != "none"){
      valcheck += "DISPLAY";
      desc += string('Auﬂerdem sollte das Flag S (suid) nur gesetzt werden, wenn die\ndamit evtl. verbundenen Sicherheitsprobleme gekl‰rt sind.\nPr¸fen Sie von daher folgenden Eintrag:\n' + lsmlocalp + '\n');
    }
    if (incaliases != "none"){
      valcheck += "DISPLAY";
      desc += string('Folgende Dateien, die von sendmail ausgewertet werden wie z. B.\n:include: in Mailing Listen, sollte nur von root beschreibbar\nsein und auch nur in root gehˆrenden Verzeichnissen stehen:\n' + incaliases + '\n');
    }
    if (lsqueue != "noperm" && lsqueue != "none"){
      valcheck += "DISPLAY";
      desc += string('Die Queue-Dateien sollten die Berechtigung 0600 haben:\n' + lsqueue + '\n');
    }
  }
  else {
    result = string("Fehler");
    desc = string("Die Datei -/etc/mail/sendmail.cf- konnte nicht gefunden werden.");
  }
}

if("FAIL" >< valcheck){
  result = string("nicht erf¸llt");
}else if(valcheck && ("FAIL" >!< valcheck && "DISPLAY" >< valcheck)){
  result = string("unvollst‰ndig");
}else if(valcheck && ("FAIL" >!< valcheck && "DISPLAY" >!< valcheck)){
  result = string("erf¸llt");
}



if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M5_019/result", value:result);
set_kb_item(name:"GSHB/M5_019/desc", value:desc);
set_kb_item(name:"GSHB/M5_019/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_019');

exit(0);
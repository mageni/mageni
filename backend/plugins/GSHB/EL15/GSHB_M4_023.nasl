###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_023.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.023
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
  script_oid("1.3.6.1.4.1.25623.1.0.94194");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"registry");
  script_name("IT-Grundschutz M4.023: Sicherer Aufruf ausf¸hrbarer Dateien");
  script_add_preference(name:"Alle Dateien Auflisten", type:"checkbox", value:"no");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04023.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_PathVariables.nasl", "GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_executable_path.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M4.023: Sicherer Aufruf ausf¸hrbarer Dateien.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.023: Sicherer Aufruf ausf¸hrbarer Dateien\n';

gshbm =  "IT-Grundschutz M4.023: ";

include("ssh_func.inc");

OSVER = get_kb_item("WMI/WMI_OSVER");
OSWINDIR = get_kb_item("WMI/WMI_OSWINDIR");
WINPATH = get_kb_item("WMI/WinPathVar");
if (WINPATH) WINPATHFOR = split(WINPATH, sep:";", keep:0);
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

executable = get_kb_item("GSHB/executable");
writeexecutable = get_kb_item("GSHB/write-executable");
path = get_kb_item("GSHB/path");
exlog = get_kb_item("GSHB/executable/log");

log = get_kb_item("WMI/WinPathVar/log");

verbose = script_get_preference("Alle Dateien Auflisten");

if(OSVER >!< "none"){
  if(!OSVER || isnull(WINPATHFOR)){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else
  {
    for(p=0; p<max_index(WINPATHFOR); p++)
    {
      if(OSWINDIR >!< WINPATHFOR[p])PATH = "FALSE";
      else PATH = "TRUE";
      PATHCHECK = PATHCHECK + PATH;
    }
    WINPATH = ereg_replace(string:WINPATH, pattern: ';', replace:';\\n');
    if ("FALSE" >< PATHCHECK){
      result = string("nicht erf¸llt");
      desc = string('Das System enth‰lt folgende PATH-Variable:\n' + WINPATH + '\nBitte pr¸fen Sie auch die Benutzervariablen, da nur\ndie Systemvariable f¸r PATH gepr¸ft werden konnte.');
    }else{
      result = string("erf¸llt");
      desc = string('Das System enth‰lt folgende PATH-Variable:\n' + WINPATH + '\nBitte pr¸fen Sie auch die Benutzervariablen, da nur\ndie Systemvariable f¸r PATH gepr¸ft werden konnte.');
    }
  }
}else if(executable !~ "(I|i)nvalid switch" && writeexecutable !~ "(I|i)nvalid switch" ){

  path = split(path, sep:'"', keep:0);
  path = split(path[1], sep:":", keep:0);
  for (i=0; i<max_index(path); i++){
    if (path[i] >!< "./") continue;
    Lst1 += path[i] + ":";
  }
  if (!Lst1) path = "none";
  else path = Lst1;

  if(executable >< "error"){
    result = string("Fehler");
    if (!exlog)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
    if (exlog && log)desc = string('Beim Testen des Systems traten folgende Fehler auf:\n'+ log + '\n' + exlog);
    else if (exlog && !log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + exlog);
  }else if(path >!< "none" || executable >!< "none" || writeexecutable >!< "none"){
    result = string("nicht erf¸llt");
    if (path >!< "none") desc = string('Folgende PATH-Variable sollte entfernt werden:\n' + path + '\n\n');
    if (writeexecutable >!< "none") desc += string('\nFolgende Dateien sind f¸r Benutzer ausf¸hrbar und\nbeschreibbar:\n' + writeexecutable + '\n\n');
    if (verbose == "yes"){
      if (executable >!< "none") desc += string('Folgende, auﬂerhalb von /usr/local/bin/:/usr/bin/:\n/bin/:/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:\n/var/lib/:/lib/:/usr/lib/:/etc/, liegende\nDateien sind f¸r Benutzer ausf¸hrbar und sollten\nentfernt bzw. die Rechte ge‰ndert werden:\n' + executable + '\n\n');
    }else{
      if (executable >!< "none") desc += string('Auﬂerhalb von /usr/local/bin/:/usr/bin/:/bin/:\n/usr/games/:/sbin/:/usr/sbin/:/usr/local/sbin/:\n/var/lib/:/lib/:/usr/lib/:/etc/, wurden\nDateien gefunden, die f¸r Benutzer ausf¸hrbar sind.\nSie sollten entfernt, bzw. es sollten die Rechte\nge‰ndert werden.\nF¸r eine vollst‰ndige Liste w‰hlen\nSie bei den Voreinstellungen dieses Tests: Alle\nDateien Auflisten\n');
    }
  }else{
    result = string("erf¸llt");
    desc = string("Das System gen¸gt den Anforderungen\nder Maﬂnahme 4.023.\n");
   }

}else {
  if (path =~ "/cygdrive/./(W|w)indows"){
    result = string("Fehler");
    if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
    if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
  }else{
    result = string("Fehler");
    if (!exlog)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
    if (exlog)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + exlog);
  }

}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}



set_kb_item(name:"GSHB/M4_023/result", value:result);
set_kb_item(name:"GSHB/M4_023/desc", value:desc);
set_kb_item(name:"GSHB/M4_023/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_023');

exit(0);

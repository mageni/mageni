###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_021.nasl 10646 2018-07-27 07:00:22Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.021
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
  script_oid("1.3.6.1.4.1.25623.1.0.94191");
  script_version("$Revision: 10646 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-27 09:00:22 +0200 (Fri, 27 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04021.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_SSH_prev_root_login.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");

  script_tag(name:"summary", value:"IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.021: Verhinderung des unautorisierten Erlangens von Administratorrechten\n';

gshbm =  "IT-Grundschutz M4.021: ";


ttynonconsole = get_kb_item("GSHB/securetty/nonconsole");
SSHDPermitRootLogin = get_kb_item("GSHB/sshdconfig/PermitRootLogin");
syslogsuenab = get_kb_item("GSHB/logindefs/syslogsuenab");
nfsexports = get_kb_item("GSHB/nfsexports");
nfsnorootsquash = get_kb_item("GSHB/nfsexports/norootsquash");
nfsrootsquash = get_kb_item("GSHB/nfsexports/rootsquash");
permsecuretty = get_kb_item("GSHB/securetty/perm");
permsshdconfig = get_kb_item("GSHB/sshdconfig/perm");
permlogindefs = get_kb_item("GSHB/logindefs/perm");
log = get_kb_item("GSHB/securetty/log");
uname = get_kb_item("GSHB/uname");


OSNAME = get_kb_item("WMI/WMI_OSNAME");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(ttynonconsole == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(ttynonconsole >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter\nFehler auf.');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}
#################
if (result != "nicht zutreffend" && result != "Fehler"){
  if(ttynonconsole >< "none" || SSHDPermitRootLogin >< "none" || syslogsuenab >< "none" || nfsexports >< "none" || ttynonconsole == "nocat" || SSHDPermitRootLogin == "nocat" || syslogsuenab == "nocat" || nfsexports == "nocat"){
    if(ttynonconsole >< "none" && uname !~ "SunOS.*"){
      result_tty = string("Fehler");
      desc = string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/securetty nicht gefunden werden\nkonnte.\n');
    }
    if(SSHDPermitRootLogin >< "none"){
      result_sshd = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/ssh/sshd_config nicht gefunden\nwerden konnte.\n');
    }
    if(syslogsuenab >< "none" && uname !~ "SunOS.*"){
      result_syslog = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/login.defs nicht gefunden werden\nkonnte.\n');
    }
    if(nfsexports >< "none" && uname !~ "SunOS.*"){
      result_nfs = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/exports nicht gefunden werden\nkonnte.\n');
    }

    if(ttynonconsole == "nocat" || SSHDPermitRootLogin == "nocat" || syslogsuenab == "nocat" || nfsexports == "nocat"){
      result_tty = string("Fehler");
      result_nfs = string("Fehler");
      result_sshd = string("Fehler");
      result_nfs = string("Fehler");
      desc = string('Fehler: Beim Testen des Systems wurde der Befehl\ncat nicht gefunden.\n');
    }
  }
#################
    if(uname !~ "SunOS.*"){
      if (ttynonconsole >< "noperm"){
        result_tty = string("Fehler");
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/securetty zu lesen.\n \n');
      }else if(ttynonconsole >< "secure"){
        result_tty = "ok";
        desc += string('Beim Testen des Systems wurden keine fehlerhafte\nEintr‰ge in der Datei /etc/securetty gefunden.\n \n');
      }else {
        result_tty = "fail";
        desc += string('Fehler: Beim Testen des Systems wurden folgende zu\nentfernende Eintr‰ge in der Datei\n/etc/securetty gefunden:\n' + ttynonconsole + '\n \n');
      }
    }
#################
    if (SSHDPermitRootLogin >< "noperm"){
      result_sshd = string("Fehler");
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/ssh/sshd_config zu lesen.\n \n');
    }else if(SSHDPermitRootLogin == "norootlogin"){
      result_sshd = "ok";
      desc += string('Beim Testen des Systems wurde festgestellt, dass\nPermitRootLogin in der Datei /etc/ssh/sshd_config\nauf no gesetzt ist.\n \n');
    }else if(SSHDPermitRootLogin == "rootlogin"){
      result_sshd = "fail";
      desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass PermitRootLogin in der Datei\n/etc/ssh/sshd_config auf yes gesetzt ist.\nƒndern Sie den Wert wenn mˆglich auf no.\n \n');
    }
#################
    if(uname !~ "SunOS.*"){
      if (syslogsuenab >< "noperm"){
        result_syslog = string("Fehler");
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/login.defs zu lesen.\n \n');
      }else if(syslogsuenab == "syslogsuenab"){
        result_syslog = "ok";
        desc += string('Beim Testen des Systems wurde festgestellt, dass\nSYSLOG_SU_ENAB in der Datei /etc/login.defs\nauf yes gesetzt ist.\n \n');
      }else if(syslogsuenab == "nosyslogsuenab"){
        result_syslog = "fail";
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass SYSLOG_SU_ENAB in der Datei /etc/login.defs auf\nno gesetzt ist. ƒndern Sie den Wert wenn mˆglich\nauf yes.\n \n');
      }
    }
#################
    if(uname !~ "SunOS.*"){
      if (nfsexports >< "noperm"){
        result_nfs = string("Fehler");
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass Sie keine Berechtigung haben die Datei\n/etc/exports zu lesen.\n \n');
      }else if(nfsnorootsquash != "none"){
        result_nfs = "fail";
        desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass der Eintrag root_squash in der Datei /etc/exports\nbei folgenden Eintr‰gen fehlt:\n' + nfsnorootsquash +'\n \n');
      }else if(nfsnorootsquash == "none" && nfsrootsquash != "none"){
        result_nfs = "ok";
        desc += string('Beim Testen des Systems wurde festgestellt, dass der\nEintrag root_squash in der Datei /etc/exports bei\nallen Eintr‰gen gesetzt ist.\n \n');
      }else if(nfsnorootsquash == "none" && nfsrootsquash == "none"){
        result_nfs = "ok";
        desc += string('Beim Testen des Systems wurde festgestellt, dass keine\nEintr‰ge/Freigaben in der Datei /etc/exports gibt.\n \n');
      }
    }
#################
  if(permsecuretty == "none" || permsshdconfig == "none" || permlogindefs == "none"){
    if(permsecuretty == "none" && uname !~ "SunOS.*"){
      result_permsecuretty = string("Fehler");
      if (result_tty != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/securetty nicht gefunden\nwerden konnte.\n \n');
    }
    if(permsshdconfig == "none"){
      result_permsshdconfig = string("Fehler");
      if (result_sshd != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/ssh/sshd_config nicht gefunden\nwerden konnte.\n \n');
    }
    if(permlogindefs == "none" && uname !~ "SunOS.*"){
      result_permlogindefs = string("Fehler");
      if (result_syslog != "Fehler")desc += string('Fehler: Beim Testen des Systems wurde festgestellt,\ndass die Datei /etc/login.defs nicht gefunden\nwerden konnte.\n \n');
    }
  }
#################
  if(permsecuretty != "none"){
    if (permsecuretty =~ "-rw-(r|-)--(r|-)--.*"){
      result_permsecuretty = string("ok");
      desc += string('Beim Testen des Systems wurden f¸r die Datei\n/etc/securetty folgende korrekte Sicherheits-\neinstellungen festgestellt:\n' + permsecuretty + '\n \n');
    }
    else{
      result_permsecuretty = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f¸r die Datei\n/etc/securetty folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: ' + permsecuretty + '\nBitte ‰ndern Sie diese auf "-rw-r--r--".\n \n' );
    }
#################
  }
  if(permsshdconfig != "none"){
    if (permsshdconfig =~ "-rw-(r|-)--(r|-)--.*"){
      result_permsshdconfig = string("ok");
      desc += string('Beim Testen des Systems wurden f¸r die Datei\n/etc/ssh/sshd_config folgende korrekte Sicherheitsein-\nstellungen festgestellt: ' + permsshdconfig + '\n \n');
    }
    else{
      result_permsshdconfig = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f¸r die Datei\n/etc/ssh/sshd_config folgende fehlerhafte Sicherheits-\neinstellungen festgestellt: ' + permsshdconfig + '\nBitte ‰ndern Sie diese auf "-rw-r--r--".\n \n' );
    }
#################
  }
  if(permlogindefs != "none"){
    if (permlogindefs =~ "-rw-(r|-)--(r|-)--.*"){
      result_permlogindefs = string("ok");
      desc += string('Beim Testen des Systems wurden f¸r die Datei\n/etc/login.defs folgende korrekte Sicherheitsein-\nstellungen festgestellt: ' + permlogindefs+ '\n \n');
    }
    else{
      result_permlogindefs = string("fail");
      desc += string('Fehler: Beim Testen des Systems wurden f¸r die Datei\n/etc/login.defs folgende fehlerhafte Sicherheitsein-\nstellungen festgestellt: ' + permlogindefs + '\nBitte ‰ndern Sie diese auf "-rw-r--r--".\n \n' );
    }
  }
#################
  if(!result && (result_tty == "fail" ||  result_sshd == "fail" || result_syslog == "fail" || result_nfs == "fail" || result_permsecuretty == "fail" || result_permsshdconfig == "fail" || result_permlogindefs == "fail")) result = string("nicht erf¸llt");
  else if(!result && (result_tty == "Fehler"|| result_sshd == "Fehler" || result_syslog == "Fehler" || result_nfs == "Fehler" || result_permsecuretty == "Fehler" || result_permsshdconfig == "Fehler" || result_permlogindefs == "Fehler")) result = string("Fehler");
  else if (!result && result_tty == "ok" && result_sshd == "ok" && result_syslog == "ok" && result_nfs == "ok" && result_permsecuretty == "ok" && result_permsshdconfig == "ok" && result_permlogindefs == "ok")result = string("erf¸llt");
#################
}

if (!result){
      result = string("Fehler");
      desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_021/result", value:result);
set_kb_item(name:"GSHB/M4_021/desc", value:desc);
set_kb_item(name:"GSHB/M4_021/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_021');

exit(0);

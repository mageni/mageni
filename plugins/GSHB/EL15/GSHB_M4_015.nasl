##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_015.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.015
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
  script_oid("1.3.6.1.4.1.25623.1.0.94182");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"package");
  script_name("IT-Grundschutz M4.015: Gesichertes Login");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04015.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_PAM.nasl", "GSHB/GSHB_WMI_PolSecSet.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M4.015: Gesichertes Login

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.015: Gesichertes Login\n';

OSNAME = get_kb_item("WMI/WMI_OSNAME");
OSVER = get_kb_item("WMI/WMI_OSVER");
WindowsDomainrole = get_kb_item("WMI/WMI_WindowsDomainrole");
DisplayLastLogonInfo = get_kb_item("WMI/cps/DisplayLastLogonInfo");
LDAPDomFunkMod = get_kb_item("GSHB/LDAP/DomFunkMod");
DomFunkMod = get_kb_item("GSHB/DomFunkMod");
if ((!DomFunkMod || DomFunkMod >< "none") && LDAPDomFunkMod) DomFunkMod = LDAPDomFunkMod;
else if (LDAPDomFunkMod && int(LDAPDomFunkMod) > 2 && int(LDAPDomFunkMod) > int(DomFunkMod))DomFunkMod = LDAPDomFunkMod;

if (DomFunkMod == 0)level = "Windows 2000 gemischt und Windows 2000 pur";
else if (DomFunkMod == 1)level = "Windows Server 2003 Interim";
else if (DomFunkMod == 2)level = "Windows Server 2003";
else if (DomFunkMod == 3)level = "Windows Server 2008";
else if (DomFunkMod == 4)level = "Windows Server 2008 R2";

uname = get_kb_item("GSHB/PAM/uname");
solpamconf = get_kb_item("GSHB/PAM/CONF");

pamlogin = get_kb_item("GSHB/PAM/login");
login_pamlastlog = get_kb_item("GSHB/PAM/login/lastlog");
login_pamlimits = get_kb_item("GSHB/PAM/login/limits");
login_pamtally = get_kb_item("GSHB/PAM/login/tally");

pamsshd = get_kb_item("GSHB/PAM/sshd");
sshd_pamlastlog = get_kb_item("GSHB/PAM/sshd/lastlog");
sshd_pamlimits = get_kb_item("GSHB/PAM/sshd/limits");
sshd_pamtally = get_kb_item("GSHB/PAM/sshd/tally");

pamgdm = get_kb_item("GSHB/PAM/gdm");
gdm_pamlastlog = get_kb_item("GSHB/PAM/gdm/lastlog");
gdm_pamlimits = get_kb_item("GSHB/PAM/gdm/limits");
gdm_pamtally = get_kb_item("GSHB/PAM/gdm/tally");

pamxdm = get_kb_item("GSHB/PAM/xdm");
xdm_pamlastlog = get_kb_item("GSHB/PAM/xdm/lastlog");
xdm_pamlimits = get_kb_item("GSHB/PAM/xdm/limits");
xdm_pamtally = get_kb_item("GSHB/PAM/xdm/tally");

pamkde = get_kb_item("GSHB/PAM/kde");
kde_pamlastlog = get_kb_item("GSHB/PAM/kde/lastlog");
kde_pamlimits = get_kb_item("GSHB/PAM/kde/limits");
kde_pamtally = get_kb_item("GSHB/PAM/kde/tally");

limits = get_kb_item("GSHB/PAM/limits");

log = get_kb_item("GSHB/PAM/log");

if(OSNAME >!< "none"){
  if (WindowsDomainrole == "0" || WindowsDomainrole == "2"){
    result = string("nicht zutreffend");
    desc = string('Das System ist kein Mitglied in einer Windows Domain.\nDer Test kann nur auf Windows Domain Mitglieder\nausgef¸hrt werden.');
  }else if(DomFunkMod >< "none" && !LDAPDomFunkMod){
    result = string("Fehler");
    desc = string('Bitte konfigurieren Sie den DomainFunktionslevel in\nden Einstellungen (Network Vulnerability Test Pre-\nferences) unter Compliance Tests/Windows Domaenen-\nfunktionsmodus!');
  }else if(int(OSVER) < 6){
    result = string("nicht zutreffend");
    desc = string('Folgendes System wurde erkannt:\n' + OSNAME + '\nDie notwendige Konfiguration ist erst ab\nWindows Vista mˆglich.');
  }else if(int(DomFunkMod) < 3){
    result = string("nicht zutreffend");
    desc = string('Das System ist Mitglied in einer Windows Domain die im\nFunktionslevel "' + level + '" l‰uft.\nDie notwendige Konfiguration ist erst ab dem\nFunktionslevel "Windows Server 2008" mˆglich.');
  }else {
    if (!DisplayLastLogonInfo){
      result = string("nicht erf¸llt");
      desc = string('"Informationen zu vorherigen Anmeldungen bei der\nBenutzeranmeldung anzeigen" wurde in keiner\nGruppenrichtlinie gesetzt.');
    }else if(DisplayLastLogonInfo == "1"){
      result = string("erf¸llt");
      desc = string('"Informationen zu vorherigen Anmeldungen bei der\nBenutzeranmeldung anzeigen" wurde innerhalb einer\nGruppenrichtlinie gesetzt.');
    }
  }
}else if(pamlogin == "windows") {
    result = string("nicht zutreffend");
    desc = string('Das System scheint ein Windows-System zu sein wurde\naber nicht richtig erkannt.');
}else if (uname =~ "SunOS .*"){
  if (solpamconf >< "none"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems trat ein Fehler auf:\n/etc/pam.conf konnte nicht gelesen werden.');
  }else if (solpamconf >< "read"){
    result = string("unvollst‰ndig");
    desc = string('Das System ist ein ' + uname + ' System.\nZur Zeit kˆnnen diese Systeme noch nicht getestet\nwerden.');
  }
}else if(pamlogin >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf, siehe Log Message!');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if(pamlogin == "none" && pamsshd == "none" && pamgdm == "none" && pamxdm == "none" && pamkde == "none"){
  result = string("Fehler");
  desc = string('Die Dateien /etc/pam.d/login, /etc/pam.d/sshd,\n/etc/pam.d/gdm, /etc/pam.d/xdm und /etc/pam.d/kde\nkonnten nicht gelesen werden.');
}else{

  if (pamlogin == "read"){
    if(login_pamlastlog == "fail" || login_pamlimits == "fail" || login_pamtally == "fail"){
      login_result = string("ne");
      if (login_pamlastlog == "fail")login_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/login nicht gesetzt.\n');
      if (login_pamlimits == "fail")login_desc += string('pam_limits.so ist in der Konfigurationsdatei\n/etc/pam.d/login nicht gesetzt.\n');
      if (login_pamtally == "fail")login_desc += string('pam_tally.so ist in der Konfigurationsdatei\n/etc/pam.d/login nicht gesetzt.');
    }else if (login_pamlastlog != "fail" && login_pamlimits != "fail" && login_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        login_result = string("e");
        if (login_pamlastlog == "true")login_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/login gesetzt. Sie sollten aber auch die\nOption showfailed setzen, um Erfolglose Login-Versuche\ndem Benutzer beim Login zu melden.');
        else if (login_pamlastlog == "truefail")login_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/login gesetzt.\nFolgende Eintr‰ge stehen in der Datei\n/etc/security/limits.conf:\n' + limits);
      }else{
        login_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        login_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/login gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf\n' + val);
      }
    }

  }else{
    login_result = string("F");
    login_desc = string('Die Konfigurationsdatei /etc/pam.d/login wurde nicht\ngefunden');
  }
  if (pamsshd == "read"){
    if(sshd_pamlastlog == "fail" || sshd_pamlimits == "fail" || sshd_pamtally == "fail"){
      sshd_result = string("ne");
      if (sshd_pamlastlog == "fail")sshd_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/sshd nicht gesetzt.\n');
      if (sshd_pamlimits == "fail")sshd_desc += string('pam_limits.so ist in der Konfigurationsdatei\n/etc/pam.d/sshd nicht gesetzt.\n');
      if (sshd_pamtally == "fail")sshd_desc += string('pam_tally.so ist in der Konfigurationsdatei\n/etc/pam.d/sshd nicht gesetzt.');
    }else if (sshd_pamlastlog != "fail" && sshd_pamlimits != "fail" && sshd_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        sshd_result = string("e");
        if (sshd_pamlastlog == "true")sshd_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/sshd gesetzt.\nSie sollten aber auch die\nOption showfailed setzen, um Erfolglose Login-Versuche\ndem Benutzer beim login zu melden.');
        else if (sshd_pamlastlog == "truefail")sshd_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/sshd gesetzt.\nFolgende Eintr‰ge stehen in der Datei\n/etc/security/limits.conf:\n' + limits);
      }else{
        sshd_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        sshd_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/sshd gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf\n' + val);
      }
    }
  }else{
    sshd_result = string("F");
    sshd_desc = string('Die Konfigurationsdatei /etc/pam.d/sshd wurde nicht\ngefunden');
  }
  if (pamgdm == "read"){
    if(gdm_pamlastlog == "fail" || gdm_pamlimits == "fail" || gdm_pamtally == "fail"){
      gdm_result = string("ne");
      if (gdm_pamlastlog == "fail")gdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/gdm nicht gesetzt.\n');
      if (gdm_pamlimits == "fail")gdm_desc += string('pam_limits.so ist in der Konfigurationsdatei\n/etc/pam.d/gdm nicht gesetzt.\n');
      if (gdm_pamtally == "fail")gdm_desc += string('pam_tally.so ist in der Konfigurationsdatei\n/etc/pam.d/gdm nicht gesetzt.');
    }else if (gdm_pamlastlog != "fail" && gdm_pamlimits != "fail" && gdm_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        gdm_result = string("e");
        if (gdm_pamlastlog == "true")gdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/gdm gesetzt. Sie sollten aber auch die\nOption showfailed setzen, um Erfolglose Login-Versuche\ndem Benutzer beim login zu melden.');
        else if (gdm_pamlastlog == "truefail")gdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/gdm gesetzt.\nFolgende Eintr‰ge stehen in der Datei\n/etc/security/limits.conf:\n' + limits);
      }else{
        gdm_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        gdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/gdm gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf\n' + val);
      }
    }
  }else{
    gdm_result = string("nz");
    gdm_desc = string('Die Konfigurationsdatei /etc/pam.d/gdm wurde nicht\ngefunden');
  }
  if (pamxdm == "read"){
    if(xdm_pamlastlog == "fail" || xdm_pamlimits == "fail" || xdm_pamtally == "fail"){
      xdm_result = string("ne");
      if (xdm_pamlastlog == "fail")xdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/xdm nicht gesetzt.\n');
      if (xdm_pamlimits == "fail")xdm_desc += string('pam_limits.so ist in der Konfigurationsdatei\n/etc/pam.d/xdm nicht gesetzt.\n');
      if (xdm_pamtally == "fail")xdm_desc += string('pam_tally.so ist in der Konfigurationsdatei\n/etc/pam.d/xdm nicht gesetzt.');
    }else if (xdm_pamlastlog != "fail" && xdm_pamlimits != "fail" && xdm_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        xdm_result = string("e");
        if (xdm_pamlastlog == "true")xdm_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/xdm gesetzt.\nSie sollten aber auch die\nOption showfailed setzen, um Erfolglose Login-Versuche\ndem Benutzer beim login zu melden.');
        else if (xdm_pamlastlog == "truefail")xdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/xdm gesetzt.\nFolgende Eintr‰ge stehen in der Datei\n/etc/security/limits.conf:\n' + limits);
      }else{
        xdm_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        xdm_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/xdm gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf\n' + val);
      }
    }
  }else{
    xdm_result = string("nz");
    xdm_desc = string('Die Konfigurationsdatei /etc/pam.d/xdm wurde nicht\ngefunden');
  }
  if (pamkde == "read"){
    if(kde_pamlastlog == "fail" || kde_pamlimits == "fail" || kde_pamtally == "fail"){
      kde_result = string("ne");
      if (kde_pamlastlog == "fail")kde_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/kde nicht gesetzt.\n');
      if (kde_pamlimits == "fail")kde_desc += string('pam_limits.so ist in der Konfigurationsdatei\n/etc/pam.d/kde nicht gesetzt.\n');
      if (kde_pamtally == "fail")kde_desc += string('pam_tally.so ist in der Konfigurationsdatei\n/etc/pam.d/kde nicht gesetzt.');
    }else if (kde_pamlastlog != "fail" && kde_pamlimits != "fail" && kde_pamtally != "fail"){
      if (limits != "none" && limits != "empty" && limits != "novalentrys"){
        kde_result = string("e");
        if (kde_pamlastlog == "true")kde_desc = string('pam_lastlog.so ist in der Konfigurationsdatei\n/etc/pam.d/kde gesetzt.\nSie sollten aber auch die\nOption showfailed setzen, um Erfolglose Login-Versuche\ndem Benutzer beim login zu melden.');
        else if (kde_pamlastlog == "truefail")kde_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/kde gesetzt.\nFolgende Eintr‰ge stehen in der Datei\n/etc/security/limits.conf:\n' + limits);
      }else{
        kde_result = string("ne");
        if (limits == "none") val = "nicht vorhanden.";
        else if (limits == "empty") val = "leer.";
        else if (limits == "novalentrys") val = "nur mit auskommentierten Eintr‰gen gef¸llt.";
        kde_desc = string('pam_lastlog.so, pam_limits.so und pam_tally.so sind in\nder Konfigurationsdatei /etc/pam.d/kde gesetzt.\nAllerdings ist die Datei /etc/security/limits.conf\n' + val);
      }
    }
  }else{
    kde_result = string("nz");
    kde_desc = string('Die Konfigurationsdatei /etc/pam.d/kde wurde nicht\ngefunden');
  }
  if (sshd_result == "ne" || sshd_result == "ne" || gdm_result == "ne" || xdm_result == "ne" || kde_result == "ne"){
    result = string("nicht erf¸llt");
    if (login_result == "ne") desc = login_desc;
    if (sshd_result == "ne") desc += '\n' + sshd_desc;
    if (gdm_result == "ne") desc += '\n' + gdm_desc;
    if (xdm_result == "ne") desc += '\n' + xdm_desc;
    if (kde_result == "ne") desc += '\n' + kde_desc;
  }else{
    result = string("erf¸llt");
    if (login_result != "ne") desc = login_desc;
    if (sshd_result != "ne") desc += '\n' + sshd_desc;
    if (gdm_result != "ne") desc += '\n' + gdm_desc;
    if (xdm_result != "ne") desc += '\n' + xdm_desc;
    if (kde_result != "ne") desc += '\n' + kde_desc;
  }
}
if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_015/result", value:result);
set_kb_item(name:"GSHB/M4_015/desc", value:desc);
set_kb_item(name:"GSHB/M4_015/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_015');

exit(0);

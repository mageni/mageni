##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_017.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.017
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
  script_oid("1.3.6.1.4.1.25623.1.0.95052");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_active");
  script_name("IT-Grundschutz M5.017: Einsatz der Sicherheitsmechanismen von NFS");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05017.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("GSHB/GSHB_WMI_OSInfo.nasl", "GSHB/GSHB_SSH_NFS.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M5.017: Einsatz der Sicherheitsmechanismen von NFS

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M5.017: Einsatz der Sicherheitsmechanismen von NFS\n';

OSNAME = get_kb_item("WMI/WMI_OSNAME");

exports = get_kb_item("GSHB/NFS/exports");
dfstab = get_kb_item("GSHB/NFS/dfstab");
passwd = get_kb_item("GSHB/NFS/passwd");
fstab = get_kb_item("GSHB/NFS/fstab");
vfstab = get_kb_item("GSHB/NFS/vfstab");
#keyserv = get_kb_item("GSHB/NFS/keyserv");
lsexports = get_kb_item("GSHB/NFS/lsexports");
lsdfstab = get_kb_item("GSHB/NFS/lsdfstab");
lspasswd = get_kb_item("GSHB/NFS/lspasswd");
lsfstab = get_kb_item("GSHB/NFS/lsfstab");
lsvfstab = get_kb_item("GSHB/NFS/lsvfstab");

nfsd = get_kb_item("GSHB/NFS/nfsd");
mountd = get_kb_item("GSHB/NFS/mountd");

log = get_kb_item("GSHB/NFS/log");

if(OSNAME >!< "none"){
  result = string("nicht zutreffend");
  desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nFolgendes System wurde erkannt:\n' + OSNAME);
}else if(exports == "windows") {
    result = string("nicht zutreffend");
    desc = string('Dieser Test bezieht sich auf UNIX/LINUX Systeme.\nDas System scheint ein Windows-System zu sein.');
}else if(exports >< "error"){
  result = string("Fehler");
  if (!log)desc = string('Beim Testen des Systems trat ein\nunbekannter Fehler auf, siehe Log Message!');
  if (log)desc = string('Beim Testen des Systems trat ein Fehler auf:\n' + log);
}else if(nfsd == "false" && mountd == "false" && exports == "none" && dfstab == "none" && (fstab !~ ".*nfs.*" && fstab !~ ".*:.*") && (vfstab !~ ".*nfs.*" && vfstab !~ ".*:.*")){
  result = string("nicht zutreffend");
  desc = string('Auf System wurden keine per NFS exportierten oder\nverbundenen Dateisysteme gefunden.');

}else{
#Hier folgen die CLIENTABFRAGEN

  if(fstab != "none"){
    Lst = split(fstab, keep:0);
    for(i=0; i<max_index(Lst); i++){
      if (Lst[i] !~ ".*nfs.*")continue;
      if (Lst[i] =~ ".*nosuid.*")continue;
      val1 += Lst[i] + '\n';
    }
  }
  if(vfstab != "none"){
    Lst = split(vfstab, keep:0);
    for(i=0; i<max_index(Lst); i++){
      if (Lst[i] !~ ".*nfs.*")continue;
      if (Lst[i] =~ ".*nosuid.*")continue;
      val2 += Lst[i] + '\n';
    }
  }
  if (val1 || val2 && (nfsd == "false" && mountd == "false")){
    cli_result = string("ne");
    cli_desc = string('Beim Testen des Systems wurden folgende Fehler\ngefunden:\n\n');
    if (val1) cli_desc += string('In der Datei /etc/fstab stehen folgende\nunzureichenden Eintr‰ge:\n' + val1 + '\n\n');
    if (val2) cli_desc += string('In der Datei /etc/vfstab stehen\nfolgende unzureichenden Eintr‰ge:\n' + val2);
  }else if (val1 || val2 && (nfsd != "false" && mountd != "false")){
    cli_result = string("ne");
    cli_desc = string('Beim Testen des Systems wurde festgestellt das das System als\nNFS Server und Client l‰uft. Auﬂerdem wurden folgende Fehler\ngefunden:\n\n');
    if (val1) cli_desc += string('In der Datei /etc/fstab stehen folgende\nunzureichenden Eintr‰ge:\n' + val1 + '\n\n');
    if (val2) cli_desc += string('In der Datei /etc/vfstab stehen folgende\nunzureichenden Eintr‰ge:\n' + val2 + '\n\n');
  }else if (((fstab =~ ".*nfs.*" && fstab =~ ".*:.*") || (vfstab =~ ".*nfs.*" && vfstab =~ ".*:.*")) && (nfsd != "false" && mountd != "false")){
    cli_result = string("ne");
    cli_desc = string('Beim Testen des Systems wurde festgestellt das das System als\nNFS Server und Client l‰uft.\n\n');
  }else if (((fstab !~ ".*nfs.*" && fstab !~ ".*:.*") || (vfstab !~ ".*nfs.*" && vfstab !~ ".*:.*")) && (nfsd == "false" && mountd == "false")){# ||!val1 && !val2  ){
    cli_result = string("e");
    if (fstab != "none" && vfstab != "none")cli_desc = string('Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/fstab und /etc/vfstab festgestellt.\n\n');
    else if (fstab != "none" && vfstab == "none")cli_desc = string('Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/fstab festgestellt.\n\n');
    else if (fstab == "none" && vfstab != "none")cli_desc = string('Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/vfstab festgestellt.\n\n');
  }


#Hier folgen die Serverabfragen
  if (exports == "ok" && (nfsd == "true" && mountd == "true")){
    serv_result = string("e");
    serv_desc = string('Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/exports festgestellt.\n\n');
  }else if ((exports == "ok" || exports == "none") && (nfsd == "false" && mountd == "false")){
    serv_result = string("e");
    serv_desc = string('Beim Testen des Systems wurde festgestellt,\ndass kein NFS Server l‰uft.\n\n');
  }else if (exports != "none" && exports != "ok" && (nfsd == "true" && mountd == "true")){
    serv_result = string("ne");
    serv_desc = string('Beim Testen des Systems wurden in der Konfigurationsdatei\n/etc/exports folgende Fehlerhafte Eintr‰ge gefunden:\n' + exports + '\n\n');
  }else if (exports == "none" && (nfsd == "true" && mountd == "true")){
    serv_result = string("ne");
    serv_desc = string('Beim Testen des Systems wurde festgestellt, das der NFS\nServer l‰uft, aber die Konfigurationsdatei /etc/exports wurde\nnicht gefunden.\n\n');
  }

  if (dfstab != "none" && dfstab == "ok"){
    serv_result = string("e");
    serv_desc += string('Beim Testen des Systems wurde kein Fehler in der\nKonfigurationsdatei /etc/dfstab festgestellt.\n\n');
  }else if (dfstab != "none" && dfstab != "ok"){
    serv_result = string("ne");
    serv_desc += string('Beim Testen des Systems wurden in der Konfigurationsdatei\n/etc/dfs/dfstab folgende Fehlerhafte Eintr‰ge gefunden:\n' + dfstab + '\n\n');
  }

#Hier folgen die passwd Abfrage

  if(passwd == "no_nobody" && (nfsd == "true" && mountd == "true")){
    passwd_result = string("ne");
    passwd_desc = string('Es sollte sichergestellt werden, dass ein Eintrag\nnobody:*:-2:-2:anonymous user:: in der /etc/passwd existiert\nund wirksam ist.\n\n');
  }else if(passwd == "nobody" && (nfsd == "true" && mountd == "true")){
    passwd_result = string("e");
    passwd_desc = string('Es wurde festgestellt, dass ein Eintrag\nnobody:*:-2:-2:anonymous user:: in der /etc/passwd existiert.\n\n');
  }else passwd_result = string("e");


#Hier folgt die Zugriffsrechte Abfrage

  if (lsexports != "none" && lsexports !~"-rw-r--r--.*"){
    lsexports_result = string("ne");
    lsexports_desc = string('Die Zugriffrechte auf /etc/exports sollten immer 644 sein.\n\n');
  }
  if (lsdfstab != "none" && lsdfstab !~"-rw-r--r--.*"){
    lsdfstab_result = string("ne");
    lsdfstab_desc = string('Die Zugriffrechte auf /etc/dfs/dfstab sollten immer 644 sein.\n\n');
  }
  if (lspasswd != "none" && lspasswd !~"-rw-r--r--.*"){
    lspasswd_result = string("ne");
    lspasswd_desc = string('Die Zugriffrechte auf /etc/passwd sollten immer 644 sein.\n\n');
  }
  if (lsfstab != "none" && lsfstab !~"-rw-r--r--.*"){
    lsfstab_result = string("ne");
    lsfstab_desc = string('Die Zugriffrechte auf /etc/fstab sollten immer 644 sein.\n\n');
  }
  if (lsvfstab != "none" && lsvfstab !~"-rw-r--r--.*"){
    lsvfstab_result = string("ne");
    lsvfstab_desc = string('Die Zugriffrechte auf /etc/vfstab sollten immer 644 sein.\n\n');
  }
}

if (serv_result == "ne" || cli_result == "ne" || passwd_result == "ne" || lsexports_result == "ne" || lsdfstab_result == "ne" || lspasswd_result == "ne" || lsfstab_result == "ne" || lsvfstab_result == "ne"){
  result = string("nicht erf¸llt");
  desc = cli_desc +  serv_desc + passwd_desc + lsexports_desc + lsdfstab_desc + lspasswd_desc + lsfstab_desc + lsvfstab_desc;
}else if (serv_result == "e" && cli_result == "e" && passwd_result == "e" || (serv_result == "e" && !cli_result)  && passwd_result == "e" || (!serv_result && cli_result == "e")  && passwd_result == "e"){
  result = string("erf¸llt");
  desc = serv_desc + cli_desc + passwd_desc;
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf\nbzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M5_017/result", value:result);
set_kb_item(name:"GSHB/M5_017/desc", value:desc);
set_kb_item(name:"GSHB/M5_017/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_017');

exit(0);

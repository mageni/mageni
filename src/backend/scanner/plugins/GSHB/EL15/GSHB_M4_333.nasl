##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_333.nasl 11531 2018-09-21 18:50:24Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.333
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
  script_oid("1.3.6.1.4.1.25623.1.0.94240");
  script_version("$Revision: 11531 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-21 20:50:24 +0200 (Fri, 21 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("gather-package-list.nasl", "GSHB/GSHB_SSH_fstab.nasl", "GSHB/GSHB_SSH_Samba.nasl", "GSHB/GSHB_SSH_nsswitch.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04333.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("itg.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M4.333: Sichere Konfiguration von Winbind unter Samba\n';

samba = kb_smb_is_samba();
global = get_kb_item("GSHB/SAMBA/global");
reiserfs = get_kb_item("GSHB/FSTAB/reiserfs");
global = tolower(global);
log = get_kb_item("GSHB/SAMBA/log");
SSHUNAME = get_kb_item("ssh/login/uname");
passwd = get_kb_item("GSHB/nsswitch/passwd");
group = get_kb_item("GSHB/nsswitch/group");

if (samba || (SSHUNAME && ("command not found" >!< SSHUNAME && "CYGWIN" >!< SSHUNAME))){
  rpms = get_kb_item("ssh/login/packages");
  if (rpms){
    pkg1 = "winbind";
    pat1 = string("ii  (", pkg1, ") +([0-9]:)?([^ ]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
  }else{
    rpms = get_kb_item("ssh/login/rpms");
    tmp = split(rpms, keep:0);
    if (max_index(tmp) <= 1)rpms = ereg_replace(string:rpms, pattern:";", replace:'\n');
    pkg1 = "winbind";
    pat1 = string("(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)");
    desc1 = eregmatch(pattern:pat1, string:rpms);
  }
}
if (desc1) winbind = "yes";
else winbind = "no";



if(global != "none" && global != "novalentrys"){
  Lst = split(global,keep:0);
  for(i=0; i<max_index(Lst); i++){
    if ("security" >< Lst[i]) security = Lst[i];
    if ("idmap backend" >< Lst[i]) idmapbackend = Lst[i];
    if ("template homedir" >< Lst[i]) templatehd = Lst[i];
    if ("idmap domains" >< Lst[i]) idmapdomains = Lst[i];
    if ("idmap config" >< Lst[i]) idmapconfig += Lst[i] + '\n';
  }
}

if (!security) security = "false";
if (!idmapbackend) idmapbackend = "false";
if (!templatehd) templatehd = "false";
if (!idmapdomains) idmapdomains = "false";
if (!idmapconfig) idmapconfig = "false";
if (!passwd) passwd = "false";
if (!group) group = "false";

if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System l‰uft kein Samba-Dateiserver.');
}else if(winbind == "no"){
    result = string("nicht zutreffend");
    desc = string('Auf dem System ist winbind nicht installiert.');
}else if("winbind" >!< passwd){
    result = string("nicht zutreffend");
    desc = string('Auf dem System ist winbind ¸ber /etc/nsswitch.conf\nnicht eingebunden.');
}else if(global == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if("domain" >!< security && "ads" >!< security){
  result = string("nicht zutreffend");
  desc = string('Der Samba Server auf dem System l‰uft nicht im\n-domain- oder -ads- Security-Modus.');
}else{
  if ((idmapbackend == "false" || idmapbackend == "tdb") && reiserfs != "noreiserfs"){
    result = string("nicht erf¸llt");
    desc = string('Auf dem System l‰uft folgende Partition mit ReiserFS:\n' + reiserfs +'\nIhr -idmap backend- ist auf tdb eingestellt.\nS‰mtliche Samba-Datenbanken im TDB-Format sollten auf einer\nPartition gespeichert werden, die nicht ReiserFS als\nDateisystem verwendet.');
  }else if(templatehd == "false" || '/%d/%u' >!< templatehd){
    result = string("nicht erf¸llt");
    desc = string('Die Dom‰ne des Benutzers sollte in den Pfad seines\nHeimatverzeichnisses aufgenommen werden. Diese\nMaﬂname verhindert Namenskollisionen bei\nVertrauensstellungen.');
  }else{
    if (idmapbackend == "false" || idmapbackend == "tdb"){
      result = string("erf¸llt");
      desc = string('Existieren Vertrauensstellungen zwischen Dom‰nen im\nInformationsverbund, so muss eines der folgenden ID-\nMapping-Backends verwendet werden:\n- Backend rid mit idmap domains Konfiguration.\n- Backend ldap mit idmap domains Konfiguration.\n- Backend ad.\n- Backend nss.');
    }else if ("rid" >< idmapbackend || "ldap" >< idmapbackend){
      result = string("erf¸llt");
      if ("rid" >< idmapbackend && idmapdomains != "false" && idmapconfig != "false") desc = string('Sie benutzen das ID-Mapping-Backend -rid- mit\nfolgender Konfiguration:\n' + idmapdomains + idmapconfig);
      else if ("ldap" >< idmapbackend && idmapdomains != "false" && idmapconfig != "false") desc = string('Sie benutzen das ID-Mapping-Backend -ldap- mit\nfolgender Konfiguration:\n' + idmapdomains + idmapconfig);
      else if ("rid" >< idmapbackend && (idmapdomains == "false" || idmapconfig == "false")) desc = string('Sie benutzen das ID-Mapping-Backend -rid-.\nExistieren Vertrauensstellungen zwischen Dom‰nen im\nInformationsverbund,so muss -idmap domains-\nkonfiguriert werden.');
      else if ("ldap" >< idmapbackend && (idmapdomains == "false" || idmapconfig == "false")) desc = string('Sie benutzen das ID-Mapping-Backend -ldap-.\nExistieren Vertrauensstellungen zwischen Dom‰nen im\nInformationsverbund, so muss -idmap domains-\nkonfiguriert werden.');

    }else{
      result = string("erf¸llt");
      if ("nss" >< idmapbackend) desc = string('Sie benutzen das ID-Mapping-Backend -nss-');
      else if ("ad" >< idmapbackend) desc = string('Sie benutzen das ID-Mapping-Backend -ad-');
    }
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_333/result", value:result);
set_kb_item(name:"GSHB/M4_333/desc", value:desc);
set_kb_item(name:"GSHB/M4_333/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_333');

exit(0);

##############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_334.nasl 10396 2018-07-04 09:13:46Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.334
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
  script_oid("1.3.6.1.4.1.25623.1.0.94241");
  script_version("$Revision: 10396 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-04 11:13:46 +0200 (Wed, 04 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M4.334: SMB Message Signing und Samba");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_dependencies("GSHB/GSHB_SSH_Samba.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");
  script_mandatory_keys("Compliance/Launch/GSHB-15");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04334.html");

  script_tag(name:"summary", value:"IT-Grundschutz M4.334: SMB Message Signing und Samba

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("itg.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M4.334: SMB Message Signing und Samba\n';

samba = kb_smb_is_samba();
global = get_kb_item("GSHB/SAMBA/global");

global = tolower(global);

log = get_kb_item("GSHB/SAMBA/log");

if(global != "none" && global != "novalentrys"){
  Lst = split(global,keep:0);
  for(i=0; i<max_index(Lst); i++){
    if ("client signing" >< Lst[i]) clientsigning = Lst[i];
    if ("server signing" >< Lst[i]) serversigning = Lst[i];
    if ("domain logons" >< Lst[i]) domainlogons = Lst[i];
    if ("domain master" >< Lst[i]) domainmaster = Lst[i];
  }
}

if (!clientsigning) clientsigning = "false";
if (!serversigning) serversigning = "false";
if (!domainlogons) domainlogons = "false";
if (!domainmaster) domainmaster = "false";

if(!samba){
    result = string("nicht zutreffend");
    desc = string('Auf dem System l‰uft kein Samba-Dateiserver.');
}else if(global == "error"){
  result = string("Fehler");
  if (!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if (log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(global == "none" || global == "novalentrys"){
  result = string("Fehler");
  desc = string('\nAuf dem System wurde keine Konfiguration f¸r einen\nSamba-Dateiserver gefunden.');
}else if (("auto" >< clientsigning || "mandatory" >< clientsigning) && "yes" >< serversigning && "yes" >< domainlogons){
  result = string("erf¸llt");
  if ("no" >< domainmaster)desc = string('Samba l‰uft als BDC.');
  else desc = string('Samba l‰uft als PDC.\n');
  if ("auto" >< clientsigning)desc += string('SMB Client signing ist auf Auto eingestellt\n');
  if ("mandatory" >< clientsigning)desc += string('SMB Client signing ist auf Mandatory eingestellt\n');
  desc += string('und Server signing ist aktiviert.');
}else if (("auto" >< clientsigning || "mandatory" >< clientsigning) && "no" >< serversigning && ("no" >< domainlogons || domainlogons == "false")){
  result = string("erf¸llt");
  if ("auto" >< clientsigning)desc = string('SMB Client signing ist auf Auto eingestellt\n');
  if ("mandatory" >< clientsigning)desc = string('SMB Client signing ist auf Mandatory eingestellt\n');
  desc += string('und Server signing ist nicht aktiviert. Samba l‰uft\nals Fileserver.');
}else if ((("no" >< clientsigning || clientsigning == "false") || ("no" >< serversigning || serversigning == "false")) && "yes" >< domainlogons){
  result = string("nicht erf¸llt");
  if ("no" >< domainmaster)desc = string('Samba l‰uft als BDC.\n');
  else desc = string('Samba l‰uft als PDC.\n');
  if ("no" >< clientsigning || clientsigning == "false")desc += string('Client signing ist nicht aktiviert.\n');
  if ("no" >< serversigning || serversigning == "false")desc += string('Server signing ist nicht aktiviert.\n');
}else if ("no" >< clientsigning && "no" >< domainlogons){
  result = string("unvollst‰ndig");
  desc = string('Samba l‰uft als Fileserver. Client signing ist nicht\naktiviert. Bitte pr¸fen Sie ob Windows Systeme auf die\nFreigaben zugreifen und aktivieren Sie ggf.\nClient signing.');
}else if (clientsigning == "false" && serversigning == "false" && (domainlogons == "false" || "no" >< domainlogons)){
  result = string("unvollst‰ndig");
  desc = string('Samba l‰uft als Fileserver. Client und Server signing\nsind nicht konfiguriert. Bitte pr¸fen Sie ob Windows\nSysteme auf die Freigaben zugreifen und aktivieren Sie\nggf. Client signing.');
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler\nauf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M4_334/result", value:result);
set_kb_item(name:"GSHB/M4_334/desc", value:desc);
set_kb_item(name:"GSHB/M4_334/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_334');

exit(0);

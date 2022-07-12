###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M4_080.nasl 10623 2018-07-25 15:14:01Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 4.080
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
  script_oid("1.3.6.1.4.1.25623.1.0.94208");
  script_version("$Revision: 10623 $");
  script_tag(name:"last_modification", value:"$Date: 2018-07-25 17:14:01 +0200 (Wed, 25 Jul 2018) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IT-Grundschutz M4.080: Sichere Zugriffsmechanismen bei Fernadministration");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m04/m04080.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15", "Tools/Present/wmi");
  script_dependencies("snmp_default_communities.nasl", "tftpd_detect.nasl", "GSHB/GSHB_WMI_OSInfo.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M4.080: Sichere Zugriffsmechanismen bei Fernadministration.

Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");

name = 'IT-Grundschutz M4.080: Sichere Zugriffsmechanismen bei Fernadministration\n';
gshbm =  "IT-Grundschutz M4.080: ";

OSVER = get_kb_item("WMI/WMI_OSVER");
log = get_kb_item("WMI/WMI_OS/log");
TFTP = get_kb_item("Services/udp/tftp");
FTP = get_kb_item("Ports/tcp/21");
communities = get_kb_list("SNMP/*/v12c/detected_community");
WMIOSLOG = get_kb_item("WMI/WMI_OS/log");

# avoid report if snmp_default_communities.nasl had an issue and is reporting too many communities
all_communities = get_kb_list("SNMP/*/v12c/all_communities");

if (WMIOSLOG == "On the Target System runs Samba, it is not an Microsoft System."){
  result = string("nicht zutreffend");
  desc = string("Auf dem System l‰uft Samba, es ist kein\nMicrosoft Windows System.");
}else if(!OSVER || OSVER >< "none"){
  result = string("Fehler");
  if(!log) desc = string("Beim Testen des Systems trat ein Fehler auf.");
  if(log) desc = string("Beim Testen des Systems trat ein Fehler auf:\n" + log);
}else if(!TFTP && (!communities || all_communities) && !FTP ){
  result = string("erf¸llt");
  desc = string("Das System entspricht der Maﬂnahme M4.080.");
}else{
  result = string("nicht erf¸llt");
  if (TFTP == 69)desc += string("Auf dem System l‰uft ein TFTP-Server.\n‹berpr¸fen Sie bitte ob dies notwendig ist.\n");
  if (FTP == 1)desc += string('Auf dem System l‰uft ein FTP-Server.\n‹berpr¸fen Sie bitte ob dies notwendig ist.\n');
  if (communities && !all_communities) {
    desc += string('Auf dem System existieren folgende standardm‰ﬂig\nvoreingestellten Community-Namen:\n');
    foreach community( communities ) {
      desc += community + '\n';
    }
  }
}

set_kb_item(name:"GSHB/M4_080/result", value:result);
set_kb_item(name:"GSHB/M4_080/desc", value:desc);
set_kb_item(name:"GSHB/M4_080/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M4_080');

exit(0);

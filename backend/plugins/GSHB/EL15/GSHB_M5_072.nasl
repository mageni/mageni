###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_072.nasl 14124 2019-03-13 07:14:43Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.072
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
  script_oid("1.3.6.1.4.1.25623.1.0.95068");
  script_version("$Revision: 14124 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-13 08:14:43 +0100 (Wed, 13 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("GSHB/GSHB_WMI_Netstat_natcp.nasl", "GSHB/GSHB_SSH_netstat.nasl", "smb_nativelanman.nasl", "netbios_name_get.nasl");

  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05072.html");

  script_tag(name:"summary", value:"IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste.

  Stand: 14. Erg‰nzungslieferung (14. EL).

  Hinweis: Lediglich Anzeige der in Frage kommenden Dienste.");

  script_tag(name:"qod_type", value:"remote_active");

  exit(0);
}

include("itg.inc");
include("smb_nt.inc");

name = 'IT-Grundschutz M5.072: Deaktivieren nicht benˆtigter Netzdienste\n';

gshbm =  "GSHB Maﬂnahme 5.072: ";

WMINetstat = get_kb_item("GSHB/WMI/NETSTAT");
SSHNetstat = get_kb_item("GSHB/SSH/NETSTAT");
SAMBA = kb_smb_is_samba();

if(SAMBA && SSHNetstat >< "nosock"){
  result = string("Fehler");
  desc = string('Beim Testen des Systems wurde festgestellt, dass keine SSH Verbindung aufgebaut werden konnte.');

}else if(SAMBA && SSHNetstat >!< "nosock"){
  if (SSHNetstat >!< "none"){
    result = string("unvollst‰ndig");
    desc = string('Bitte pr¸fen Sie das Ergebnis und deaktivieren ggf. nicht benˆtigter Netzdienste:\n\n' + SSHNetstat);
  }else if (SSHNetstat >< "none"){
    result = string("Fehler");
    desc = string('Es konnte ¸ber "netstat" kein Ergebnis ermittelt werden.');
  }
}else if(!SAMBA){
  if(WMINetstat >< "nocred"){
    result = string("Fehler");
    desc = string('Beim Testen des Systems wurde festgestellt, dass keine Logindaten angegeben wurden.');
  }else if(WMINetstat >< "toold"){
    result = string("Fehler");
    desc = string('Ihre GVM/GSM Installation ist zu alt.');
  }else if(WMINetstat >!< ""){
    result = string("unvollst‰ndig");
    desc = string('Bitte pr¸fen Sie das Ergebnis, und deaktivieren ggf. nicht benˆtigter Netzdienste:\n\n' + WMINetstat);
  }
}

if (!result){
  result = string("Fehler");
  desc = string('Beim Testen des Systems trat ein unbekannter Fehler auf bzw. es konnte kein Ergebnis ermittelt werden.');
}

set_kb_item(name:"GSHB/M5_072/result", value:result);
set_kb_item(name:"GSHB/M5_072/desc", value:desc);
set_kb_item(name:"GSHB/M5_072/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_072');

exit(0);
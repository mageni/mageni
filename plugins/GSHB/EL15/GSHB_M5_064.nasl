###############################################################################
# OpenVAS Vulnerability Test
# $Id: GSHB_M5_064.nasl 13570 2019-02-11 10:39:55Z cfischer $
#
# IT-Grundschutz, 14. EL, Maﬂnahme 5.064
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
  script_oid("1.3.6.1.4.1.25623.1.0.95065");
  script_version("$Revision: 13570 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 11:39:55 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-25 10:14:11 +0100 (Wed, 25 Mar 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"qod_type", value:"remote_banner");
  script_name("IT-Grundschutz M5.064: Secure Shell");
  script_xref(name:"URL", value:"http://www.bsi.bund.de/DE/Themen/ITGrundschutz/ITGrundschutzKataloge/Inhalt/_content/m/m05/m05064.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH");
  script_family("IT-Grundschutz-15");
  script_mandatory_keys("Compliance/Launch/GSHB-15");
  script_dependencies("compliance_tests.nasl", "find_service.nasl", "ssh_detect.nasl");
  script_tag(name:"summary", value:"IT-Grundschutz M5.064: Secure Shell.

  Stand: 14. Erg‰nzungslieferung (14. EL).");

  exit(0);
}

include("itg.inc");
include("ssh_func.inc");
include("version_func.inc");

name = 'IT-Grundschutz M5.064: Secure Shell\n';
gshbm =  "IT-Grundschutz M5.064: ";

port = kb_ssh_transport();

sock = ssh_login_or_reuse_connection();
if(!sock) {
  sshsock = "no";
} else if(sock) {
  sshsock = "yes";
  close(sock);
}

telnet = get_kb_item("Services/telnet");

sshbanner = get_ssh_server_banner(port:port);
if (sshbanner){
  sshbanner = tolower(sshbanner);
  version = eregmatch(pattern:"ssh-.*openssh[_-]{1}([0-9.]+[p0-9]*)", string: sshbanner);
}
else sshbanner = "none";

if(sshbanner == "none" && sshsock = "no"){
  result = string("nicht zutreffend");
  desc = string("Es wurde kein SSH-Server gefunden");
}else if(sshbanner == "none" && sshsock = "yes"){
  result = string("unvollst‰ndig");
  desc = string("Es wurde ein SSH-Server gefunden. Allerdings konnte weder der\nTyp noch die Version erkannt werden.");
}else if("openssh" >< sshbanner){
  if (telnet){
    result = string("nicht erf¸llt");
    desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden:\n' + sshbanner + '\nZus‰tzlich scheint auf Port 23 ein Telnet Server zu laufen.\nNach Mˆglichkeit sollten alle anderen Protokolle, deren\nFunktionalit‰ten durch SSH abgedeckt werden, vollst‰ndig\nabgeschaltet werden.');
  }else{
    if(version_is_less(version: version[1], test_version: "5.2")){
      result = string("nicht erf¸llt");
      desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden:\n' + sshbanner + '\nVersionen vor OpenSSH 5.2 sind verwundbar.');
    }else{
      result = string("erf¸llt");
      desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden:\n' + sshbanner + '\nVersionen vor OpenSSH 5.2 sind verwundbar.');
    }
  }
}else{
  if (telnet){
    result = string("nicht erf¸llt");
    desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden:\n' + sshbanner + '\nZus‰tzlich scheint auf Port 23 ein Telnet Server zu laufen.\nNach Mˆglichkeit sollten alle anderen Protokolle, deren\nFunktionalit‰ten durch SSH abgedeckt werden,\nvollst‰ndig abgeschaltet werden.');
  }else{
    result = string("unvollst‰ndig");
    desc = string('Es wurde auf Port ' + port + ', folgender SSH-Server gefunden:\n' + sshbanner + '\nIm Moment wird nur auf OpenSSH Server getestet.\nVersionen vor OpenSSH 5.2 sind verwundbar.');
  }
}

set_kb_item(name:"GSHB/M5_064/result", value:result);
set_kb_item(name:"GSHB/M5_064/desc", value:desc);
set_kb_item(name:"GSHB/M5_064/name", value:name);

silence = get_kb_item("GSHB/silence");
if (!silence) itg_send_details (itg_id: 'GSHB/M5_064');

exit(0);
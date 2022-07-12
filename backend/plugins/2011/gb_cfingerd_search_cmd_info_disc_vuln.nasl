###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cfingerd_search_cmd_info_disc_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Cfingerd 'search' Command Information Disclosure Vulnerability
#
# Authors:
# Rachana Shetty <srachana@secpod.com>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802323");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-12 14:44:50 +0200 (Fri, 12 Aug 2011)");
  script_cve_id("CVE-1999-0259");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Cfingerd 'search' Command Information Disclosure Vulnerability");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/1811");
  script_xref(name:"URL", value:"http://archives.neohapsis.com/archives/bugtraq/1997_2/0328.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Finger abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/finger", 79);
  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain sensitive information
  that could aid in further attacks.");
  script_tag(name:"affected", value:"Cfingerd version 1.2.2");
  script_tag(name:"insight", value:"The flaw exists due to an error in the finger service which allows to list
  all usernames on the host via 'search.**' command.");
  script_tag(name:"solution", value:"Upgrade to Cfingerd version 1.2.3 or later");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is running Cfingerd service and is prone to information
  disclosure vulnerability.");
  script_xref(name:"URL", value:"http://www.infodrom.org/projects/cfingerd/finger.php");
  exit(0);
}


port = get_kb_item("Services/finger");
if(!port){
  port = 79;
}

if(! get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(! soc){
  exit(0);
}

banner = recv(socket:soc, length:2048, timeout:5);
if(banner) {
  exit(0);
}

send(socket: soc, data: string("search.**\r\n"));
fingRes = recv(socket:soc, length:2048);
close(soc);

if("Finger" >< fingRes && "Username" >< fingRes && "root" >< fingRes){
  security_message(port);
}

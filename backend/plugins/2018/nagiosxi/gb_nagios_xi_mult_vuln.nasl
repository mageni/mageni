###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_xi_mult_vuln.nasl 13172 2019-01-21 04:30:10Z ckuersteiner $
#
# Nagios XI < 5.5.0 Multiple Vulnerabilities
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:nagios:nagiosxi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112263");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_cve_id("CVE-2018-10553", "CVE-2018-10554");
  script_version("$Revision: 13172 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-21 05:30:10 +0100 (Mon, 21 Jan 2019) $");
  script_tag(name:"creation_date", value:"2018-05-02 12:20:22 +0200 (Wed, 02 May 2018)");

  script_name("Nagios XI < 5.5.0 Multiple Vulnerabilities");

  script_tag(name:"summary", value:"This host is running Nagios XI and is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The application is vulnerable due to:

  - A registered user being able to use directory traversal to read local files (CVE-2018-10553)

  - Cross-site scripting (XSS) exploitable via CSRF in various parameters (CVE-2018-10554)");

  script_tag(name:"affected", value:"Nagios XI up to and including version 5.4.13");

  script_tag(name:"solution", value:"Update to version 5.5.0 or later.");

  script_xref(name:"URL", value:"https://code610.blogspot.de/2018/04/few-bugs-in-latest-nagios-xi-5413.html");
  script_xref(name:"URL", value:"https://www.nagios.com/products/security/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2018 Greenbone Networks GmbH");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagiosxi/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE)) exit(0);
if (!vers = get_app_version(cpe:CPE, port:port)) exit(0);

if (version_is_less(version:vers, test_version:"5.5.0")) {
  report = report_fixed_ver(installed_version: vers, fixed_version:"5.5.0");
  security_message(port:port, data:report);
  exit(0);
}

exit(99);

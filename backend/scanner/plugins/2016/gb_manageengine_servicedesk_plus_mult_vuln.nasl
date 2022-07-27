###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_servicedesk_plus_mult_vuln.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# ManageEngine ServiceDesk Plus Multiple Vulnerabilities
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = 'cpe:/a:manageengine:servicedesk_plus';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106319");
  script_version("$Revision: 12149 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-09-30 10:47:53 +0700 (Fri, 30 Sep 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2016-4888", "CVE-2016-4890");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ManageEngine ServiceDesk Plus Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");

  script_tag(name:"summary", value:"ManageEngine ServiceDesk Plus is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"ServiceDesk Plus is prone to multiple vulnerabilities:

  - A stored cross-site scripting vulnerability (CVE-2016-4888).

  - Using an insecure method for generating cookies (CVE-2016-4890).");

  script_tag(name:"impact", value:"An arbitrary script may be executed on a web browser of a user that is
logged in. If an attacker obtains a user's cookie, the password contained in the cookie can be easily guessed.");

  script_tag(name:"affected", value:"ServiceDesk Plus before version 9.2 build 9228.");

  script_tag(name:"solution", value:"Upgrade to version 9.2 build 9228 or later");

  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN50347324/index.html");
  script_xref(name:"URL", value:"https://jvn.jp/en/jp/JVN72559412/index.html");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk/readme-9.2.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

vers = str_replace(string: version, find: "build", replace: ".");

if (version_is_less(version: vers, test_version: "9.2.9228")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.2 build 9228");
  security_message(port: port, data: report);
  exit(0);
}

exit(0);

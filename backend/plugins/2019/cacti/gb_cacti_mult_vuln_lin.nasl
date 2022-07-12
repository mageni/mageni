# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

CPE = "cpe:/a:cacti:cacti";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143253");
  script_version("2020-01-23T11:30:23+0000");
  script_tag(name:"last_modification", value:"2020-01-23 11:30:23 +0000 (Thu, 23 Jan 2020)");
  script_tag(name:"creation_date", value:"2019-12-16 07:05:33 +0000 (Mon, 16 Dec 2019)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:P/A:P");

  script_cve_id("CVE-2019-17358", "CVE-2019-17357");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Cacti < 1.2.8 Multiple Vulnerabilities (Linux)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("cacti_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("cacti/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"Cacti is prone to multiple vulnerabilities.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - There are multiple instances of lib/functions.php unsafe
  deserialization of user-controlled data to populate arrays. An authenticated attacker could use this to
  influence object data values and control actions taken by Cacti or potentially cause memory corruption in the
  PHP module.

  - There is an SQL injection vulnerability via graphs.php?template_id affecting how template identifiers
  are handled when a string and id composite value are used to identify the template type and id.
  An authenticated attacker can exploit this to extract data from the database, or an unauthenticated
  attacker could exploit this via Cross-Site Request Forgery.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Cacti version 1.2.7 and prior.");

  script_tag(name:"solution", value:"Update to version 1.2.8 or later.");

  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3025");
  script_xref(name:"URL", value:"https://github.com/Cacti/cacti/issues/3026");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "1.2.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.2.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

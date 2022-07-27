# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) of the respective author(s)
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

CPE = "cpe:/a:apache:roller";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142641");
  script_version("2019-07-23T10:31:33+0000");
  script_tag(name:"last_modification", value:"2019-07-23 10:31:33 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-23 09:21:49 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-0234");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Apache Roller < 5.2.3 XSS Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_roller_detect.nasl");
  script_mandatory_keys("ApacheRoller/detected");

  script_tag(name:"summary", value:"Apache Roller is prone to a reflected cross-site scripting vulnerability.");

  script_tag(name:"insight", value:"Roller's Math Comment Authenticator did not property sanitize user input and
  could be exploited to perform Reflected Cross Site Scripting (XSS).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"Roller versions 5.2, 5.2.1, 5.2.2. The unsupported pre-Roller 5.1 versions
  may also be affected.");

  script_tag(name:"solution", value:"Update to version 5.2.3 or later.");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/26cdef3fa8a8fa7fcbb99320aa860836ead124b414c654a4d12674cf@%3Cdev.roller.apache.org%3E");

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

if (version_is_less(version: version, test_version: "5.2.3")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "5.2.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

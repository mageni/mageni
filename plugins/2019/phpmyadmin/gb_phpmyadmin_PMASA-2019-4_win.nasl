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

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142500");
  script_version("2019-06-11T04:26:53+0000");
  script_tag(name:"last_modification", value:"2019-06-11 04:26:53 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-11 04:26:01 +0000 (Tue, 11 Jun 2019)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2019-12616");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpMyAdmin < 4.9.0 CSRF Vulnerability - PMASA-2019-4 (Windows)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl", "os_detection.nasl");
  script_mandatory_keys("phpMyAdmin/installed", "Host/runs_unixoide");

  script_tag(name:"summary", value:"phpMyAdmin is prone to a CSRF vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"A vulnerability was found that allows an attacker to trigger a CSRF attack
  against a phpMyAdmin user. The attacker can trick the user, for instance through a broken <img> tag pointing at
  the victim's phpMyAdmin database, and the attacker can potentially deliver a payload (such as a specific INSERT
  or DELETE statement) through the victim.");

  script_tag(name:"affected", value:"phpMyAdmin prior to version 4.9.0.");

  script_tag(name:"solution", value:"Update to version 4.9.0 or later.");

  script_xref(name:"URL", value:"https://www.phpmyadmin.net/security/PMASA-2019-4/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos['version'];
path = infos['location'];

if (version_is_less(version: version, test_version: "4.9.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.9.0", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

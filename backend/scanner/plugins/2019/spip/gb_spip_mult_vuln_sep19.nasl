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

CPE = 'cpe:/a:spip:spip';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.142924");
  script_version("2019-09-24T07:22:26+0000");
  script_tag(name:"last_modification", value:"2019-09-24 07:22:26 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"creation_date", value:"2019-09-24 07:07:58 +0000 (Tue, 24 Sep 2019)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2019-16391", "CVE-2019-16392", "CVE-2019-16393", "CVE-2019-16394");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("SPIP < 3.1.11, 3.2.x < 3.2.5 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_spip_detect.nasl");
  script_mandatory_keys("spip/detected");

  script_tag(name:"summary", value:"SPIP is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"SPIP is prone to multiple vulnerabilities:

  - Authenticated visitors may modify any published content and execute other modifications in the database (CVE-2019-16391)

  - XSS in prive/formulaires/login.php (CVE-2019-16392)

  - Mishandled redirect URLs in ecrire/inc/headers.php with a %0D, %0A, or %20 character (CVE-2019-16393)

  - Information disclosure vulnerability (CVE-2019-16394)");

  script_tag(name:"affected", value:"SPIP prior to version 3.1.11 and version 3.2.x prior to version 3.2.5.");

  script_tag(name:"solution", value:"Update to version 3.1.11, 3.2.5 or later.");

  script_xref(name:"URL", value:"https://blog.spip.net/Mise-a-jour-CRITIQUE-de-securite-Sortie-de-SPIP-3-2-5-et-SPIP-3-1-11.html");

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

if (version_is_less(version: version, test_version: "3.1.11")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.11", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "3.2", test_version2: "3.2.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.5", install_path: path);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

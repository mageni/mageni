# Copyright (C) 2022 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127040");
  script_version("2022-06-10T08:16:36+0000");
  script_tag(name:"last_modification", value:"2022-06-10 08:16:36 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"creation_date", value:"2022-06-10 09:51:43 +0000 (Fri, 10 Jun 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_cve_id("CVE-2022-1986", "CVE-2022-1992", "CVE-2022-1993", "CVE-2022-31038");

  script_name("Gogs < 0.12.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_gogs_http_detect.nasl");
  script_mandatory_keys("gogs/detected");

  script_tag(name:"summary", value:"Gogs is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-1986: The attacker is able to update a crafted config file into repository's .git
   directory in combination with crafted file deletion to gain SSH access to the server.

  - CVE-2022-1992: The attacker is able to delete and upload arbitrary file(s). All installations
   on Windows with repository upload enabled (default) are affected.

  - CVE-2022-1993: The attacker is able to craft HTTP requests to access unauthorized Git
   directories.

  - CVE-2022-31038: DisplayName allows all the characters from users, which leads to
   an XSS vulnerability when directly displayed in the issue list.");

  script_tag(name:"affected", value:"Gogs prior to version 0.12.9.");

  script_tag(name:"solution", value:"Update to version 0.12.9 or later.");

  script_xref(name:"URL", value:"https://github.com/gogs/gogs/security/advisories/GHSA-67mx-jc2f-jgjm");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/security/advisories/GHSA-994f-7g86-qr56");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/security/advisories/GHSA-6vcc-v9vw-g2x5");
  script_xref(name:"URL", value:"https://github.com/gogs/gogs/security/advisories/GHSA-xq4v-vrp9-vcf2");

  exit(0);
}

CPE = "cpe:/a:gogs:gogs";

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "0.12.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "0.12.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

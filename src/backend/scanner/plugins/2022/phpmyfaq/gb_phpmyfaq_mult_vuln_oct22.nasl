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

CPE = "cpe:/a:phpmyfaq:phpmyfaq";

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.127242");
  script_version("2022-11-03T13:58:22+0000");
  script_tag(name:"last_modification", value:"2022-11-03 13:58:22 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-03 11:48:56 +0200 (Thu, 03 Nov 2022)");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");

  script_cve_id("CVE-2022-3754", "CVE-2022-3765", "CVE-2022-3766");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.1.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"The following vulnerabilities exist:

  - CVE-2022-3754: When users change password to a too simple password, attacker can easily guess
  user password and access account.

  - CVE-2022-3765: An malicious attacker can inject JavaScript code, steal cookie, deface website.

  - CVE-2022-3766: An malicious attacker can inject JavaScript code, steal cookie, deface
  website.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.8.");

  script_tag(name:"solution", value:"Update to version 3.1.8 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/f4711d7f-1368-48ab-9bef-45f32e356c47/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/613143a1-8e51-449a-b214-12458308835d/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/d9666520-4ff5-43bb-aacf-50c8e5570983/");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.8");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);

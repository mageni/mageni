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
  script_oid("1.3.6.1.4.1.25623.1.0.127278");
  script_version("2022-12-13T10:10:56+0000");
  script_tag(name:"last_modification", value:"2022-12-13 10:10:56 +0000 (Tue, 13 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-12 07:48:56 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2022-4407", "CVE-2022-4408", "CVE-2022-4409");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpmyFAQ < 3.1.9 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("phpmyfaq_detect.nasl");
  script_mandatory_keys("phpmyfaq/installed");

  script_tag(name:"summary", value:"phpMyFAQ is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-4407: Reflected cross-site scripting (XSS)

  - CVE-2022-4408: Stored cross-site scripting (XSS)

  - CVE-2022-4409: TLS Cookie without `secure` flag at roy.demo.phpmyfaq.de");

  script_tag(name:"impact", value:"Attacker can execute javascript, send queries with abusive
  words, steal the cookie or redirect to any URL.");

  script_tag(name:"affected", value:"phpMyFAQ prior to version 3.1.9.");

  script_tag(name:"solution", value:"Update to version 3.1.9 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/a1649f43-78c9-4927-b313-36911872a84b/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/5915ed4c-5fe2-42e7-8fac-5dd0d032727c/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/2ec4ddd4-de22-4f2d-ba92-3382b452bfea/");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version, test_version: "3.1.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.1.9");
  security_message(data: report, port: port);
  exit(0);
}

exit(99);


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

CPE = "cpe:/a:xwiki:xwiki";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127186");
  script_version("2022-09-23T02:35:16+0000");
  script_tag(name:"last_modification", value:"2022-09-23 02:35:16 +0000 (Fri, 23 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-13 12:10:03 +0000 (Tue, 13 Sep 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");

  script_cve_id("CVE-2022-36091");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki < 13.10.4, 14.0 < 14.2 Information Disclosure Vulnerability (GHSA-599v-w48h-rjrm)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"Xwiki is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Through the suggestion feature, string and list properties of
  objects the user shouldn't have access to can be accessed. This includes private personal
  information like email addresses and salted password hashes of registered users but also other
  information stored in properties of objects. Sensitive configuration fields like passwords for
  LDAP or SMTP servers could be accessed. By exploiting an additional vulnerability, this issue can
  even be exploited on private wikis at least for string properties.");

  script_tag(name:"affected", value:"XWiki prior to version 13.10.4 and version 14.x prior to
  14.2.");

  script_tag(name:"solution", value:"Update to version 13.10.4, 14.2 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-599v-w48h-rjrm");

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

if (version_is_less(version: version, test_version: "13.10.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.10.4", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "14.0", test_version_up: "14.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "14.2", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

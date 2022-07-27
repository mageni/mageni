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
  script_oid("1.3.6.1.4.1.25623.1.0.124013");
  script_version("2022-02-24T14:03:33+0000");
  script_tag(name:"last_modification", value:"2022-02-24 14:03:33 +0000 (Thu, 24 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-11 12:04:03 +0000 (Fri, 11 Feb 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-15 18:35:00 +0000 (Tue, 15 Feb 2022)");

  script_cve_id("CVE-2022-23621");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("XWiki LFI Vulnerability (GHSA-2jhm-qp48-hv5j)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_xwiki_enterprise_detect.nasl");
  script_mandatory_keys("xwiki/detected");

  script_tag(name:"summary", value:"XWiki is prone to a local file inclusion (LFI) vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Any user with SCRIPT right (EDIT right before XWiki 7.4) can
  read any file located in the XWiki WAR.");

  script_tag(name:"affected", value:"XWiki prior to version 12.10.9, version 13.x through 13.4.2
  and 13.5.x through 13.6.x.");

  script_tag(name:"solution", value:"Update to version 12.10.9, 13.4.3, 13.7-rc-1 or later.");

  script_xref(name:"URL", value:"https://github.com/xwiki/xwiki-platform/security/advisories/GHSA-2jhm-qp48-hv5j");

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

if (version_is_less(version: version, test_version: "12.10.9")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "12.10.9", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range(version: version, test_version: "13.0", test_version2: "13.4.2")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.4.3", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "13.5", test_version_up: "13.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "13.7-rc-1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

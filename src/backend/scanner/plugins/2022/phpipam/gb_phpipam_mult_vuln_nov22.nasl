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

CPE = "cpe:/a:phpipam:phpipam";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126199");
  script_version("2022-11-08T10:12:11+0000");
  script_tag(name:"last_modification", value:"2022-11-08 10:12:11 +0000 (Tue, 08 Nov 2022)");
  script_tag(name:"creation_date", value:"2022-11-03 09:39:32 +0000 (Thu, 03 Nov 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-05 21:25:00 +0000 (Thu, 05 Mar 2020)");

  script_cve_id("CVE-2020-7988", "CVE-2022-1225", "CVE-2022-3845");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("phpIPAM < 1.5.0 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ipam_detect.nasl");
  script_mandatory_keys("phpipam/installed");

  script_tag(name:"summary", value:"phpIPAM is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - SQL injections processing `tableName`

  - SQL injections processing `ftype`

  - Stored XSS in instructions widgets

  - PHP session ID fixation

  - XSS (reflected) in IP calculator

  - CVE-2020-7988: XSS in pass-change/result.php

  - SQL injection in edit-bgp-mapping-search.php

  - Stored XSS in the 'Site title' parameter

  - XSS while uploading CVS files

  - XSS (reflected) in 'find subnets'

  - CVE-2022-1225: Incorrect privilege assignments

  - XXS (reflected) in ripe-arin-query

  - CVE-2022-3845: Reflected XSS in import previews");

  script_tag(name:"affected", value:"phpIPAM prior to 1.5.0.");

  script_tag(name:"solution", value:"Update to version 1.5.0 or later.");

  script_xref(name:"URL", value:"https://github.com/phpipam/phpipam/releases/tag/v1.5.0");

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

if (version_is_less(version: version, test_version: "1.5.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.5.0", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

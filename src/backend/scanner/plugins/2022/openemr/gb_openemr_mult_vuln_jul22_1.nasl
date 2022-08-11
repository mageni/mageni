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

CPE = "cpe:/a:open-emr:openemr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.124129");
  script_version("2022-07-29T06:04:01+0000");
  script_tag(name:"last_modification", value:"2022-07-29 06:04:01 +0000 (Fri, 29 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-25 08:04:08 +0000 (Mon, 25 Jul 2022)");
  script_tag(name:"cvss_base", value:"5.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-04 19:26:00 +0000 (Wed, 04 May 2022)");

  script_cve_id("CVE-2022-1458", "CVE-2022-1459", "CVE-2022-1461");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("OpenEMR < 6.1.0.1 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openemr_detect.nasl");
  script_mandatory_keys("openemr/installed");

  script_tag(name:"summary", value:"OpenEMR is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2022-1458: Stored cross-site scripting (XSS) leads to session hijacking

  - CVE-2022-1459: Non-privilege users (accounting, front office) can view patients disclosures and
  have the capability to add, edit and delete the patients disclosures

  - CVE-2022-1461: Non-privilege user can enable or disable registered modules");

  script_tag(name:"affected", value:"OpenEMR prior to version 6.1.0.1.");

  script_tag(name:"solution", value:"Update to version 6.1.0.1 or later.");

  script_xref(name:"URL", value:"https://huntr.dev/bounties/78674078-0796-4102-a81e-f699cd6981b0/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/9023ca9b-a601-4e5d-8952-640c60d029f1/");
  script_xref(name:"URL", value:"https://huntr.dev/bounties/690a8ec5-64fc-4180-9f1f-c3c599bae0a9/");

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

if (version_is_less(version: version, test_version: "6.1.0.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "6.1.0.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

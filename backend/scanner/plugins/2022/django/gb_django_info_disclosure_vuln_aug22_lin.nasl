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

CPE = "cpe:/a:djangoproject:django";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126100");
  script_version("2022-08-04T13:37:02+0000");
  script_tag(name:"last_modification", value:"2022-08-04 13:37:02 +0000 (Thu, 04 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-07-05 03:43:44 +0000 (Tue, 05 Jul 2022)");
  script_tag(name:"cvss_base", value:"2.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:S/C:P/I:N/A:N");

  script_cve_id("CVE-2022-36359");

  script_tag(name:"qod_type", value:"executable_version_unreliable");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Django < 3.2.15, 4.x < 4.0.7 Information Disclosure Vulnerability - Linux");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_django_detect_lin.nasl");
  script_mandatory_keys("Django/Linux/Ver");

  script_tag(name:"summary", value:"Django is prone to an information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An application may have been vulnerable to a reflected file
  download (RFD) attack that sets the ContentDisposition header of a FileResponse when the filename
  was derived from user-supplied input.");

  script_tag(name:"affected", value:"Django prior to version 3.2.15 and versions 4.x prior to 4.0.7.");

  script_tag(name:"solution", value:"Update to version 3.2.15, 4.0.7 or later.");

  script_xref(name:"URL", value:"https://www.djangoproject.com/weblog/2022/aug/03/security-releases/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "3.2.15")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "3.2.15", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

if (version_in_range_exclusive(version: version, test_version_lo: "4.0.0", test_version_up: "4.0.7")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.0.7", install_path: location);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2021 Greenbone Networks GmbH
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

CPE = "cpe:/a:owncloud:owncloud";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117618");
  script_version("2021-08-12T13:16:24+0000");
  script_tag(name:"last_modification", value:"2021-08-13 10:29:13 +0000 (Fri, 13 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-08-12 13:09:57 +0000 (Thu, 12 Aug 2021)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:C/A:N");

  script_cve_id("CVE-2021-35946", "CVE-2021-35947", "CVE-2021-35948", "CVE-2021-35949");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("ownCloud < 10.8 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_owncloud_detect.nasl");
  script_mandatory_keys("owncloud/installed");

  script_tag(name:"summary", value:"ownCloud is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The following vulnerabilities exist:

  - CVE-2021-35946: Federated share recipient can increase permissions

  - CVE-2021-35947: Full path and username disclosure in public links

  - CVE-2021-35948: Session fixation on public links

  - CVE-2021-35949: Shareinfo url doesn't verify file drop permissions");

  script_tag(name:"affected", value:"ownCloud version 10.7 and prior.");

  script_tag(name:"solution", value:"Update to version 10.8 or later.");

  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35946/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35947/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35948/");
  script_xref(name:"URL", value:"https://owncloud.com/security-advisories/cve-2021-35949/");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe: CPE, port: port, exit_no_version:TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_is_less(version: version, test_version: "10.8")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "10.8", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);
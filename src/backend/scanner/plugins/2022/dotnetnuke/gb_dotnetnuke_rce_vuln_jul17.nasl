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

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126108");
  script_version("2022-08-11T09:56:42+0000");
  script_tag(name:"last_modification", value:"2022-08-11 09:56:42 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-10 23:04:16 +0000 (Wed, 10 Aug 2022)");
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-04-03 05:15:00 +0000 (Fri, 03 Apr 2020)");

  script_cve_id("CVE-2017-9822");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("DotNetNuke < 9.1.1 RCE Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_detect.nasl");
  script_mandatory_keys("dotnetnuke/installed");

  script_tag(name:"summary", value:"DotNetNuke is prone to a remote code execution (RCE)
  vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Possible remote code execution via a cookie on DNN sites.");

  script_tag(name:"affected", value:"DotNetNuke prior to version 9.1.1.");

  script_tag(name:"solution", value:"Update to version 9.1.1 or later.");

  script_xref(name:"URL", value:"https://packetstormsecurity.com/files/cve/CVE-2017-9822");
  script_xref(name:"URL", value:"https://github.com/advisories/GHSA-x2rg-fmcv-crq5");
  script_xref(name:"URL", value:"https://dnncommunity.org/security");

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

if (version_is_less(version: version, test_version: "9.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "9.1.1", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

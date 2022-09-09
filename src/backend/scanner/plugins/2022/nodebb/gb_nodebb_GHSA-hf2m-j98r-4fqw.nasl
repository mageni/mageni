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

CPE = "cpe:/a:nodebb:nodebb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.127164");
  script_version("2022-09-09T08:44:15+0000");
  script_tag(name:"last_modification", value:"2022-09-09 08:44:15 +0000 (Fri, 09 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-07 05:21:00 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-11-30 15:57:00 +0000 (Tue, 30 Nov 2021)");

  script_cve_id("CVE-2021-43786");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("NodeBB 1.15.x - 1.18.4 Improper Authentication Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_nodebb_detect.nasl");
  script_mandatory_keys("NodeBB/installed");

  script_tag(name:"summary", value:"NodeBB is prone to an improper authentication vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Incorrect logic present in the token verification step
  unintentionally allowed master token access to the API.");

  script_tag(name:"affected", value:"NodeBB version 1.15.0 through 1.18.4.");

  script_tag(name:"solution", value:"Update to version 1.18.5 or later.");

  script_xref(name:"URL", value:"https://github.com/NodeBB/NodeBB/security/advisories/GHSA-hf2m-j98r-4fqw");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if (!port = get_app_port(cpe:CPE))
  exit(0);

if (!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version: TRUE))
  exit(0);

version = infos["version"];
location = infos["location"];

if (version_in_range(version: version, test_version: "1.15.0", test_version2: "1.18.4")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "1.18.5", install_path: location);
  security_message(port: port, data: report);
  exit(0);
}

exit(99);

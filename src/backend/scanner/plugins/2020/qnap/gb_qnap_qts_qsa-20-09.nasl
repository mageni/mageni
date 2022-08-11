# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE_PREFIX = "cpe:/h:qnap";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112840");
  script_version("2020-11-17T11:01:25+0000");
  script_tag(name:"last_modification", value:"2020-11-18 11:58:37 +0000 (Wed, 18 Nov 2020)");
  script_tag(name:"creation_date", value:"2020-11-17 09:13:11 +0000 (Tue, 17 Nov 2020)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2020-2490", "CVE-2020-2492");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("QNAP QTS Multiple Vulnerabilities (QSA-20-09)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_qnap_nas_detect.nasl");
  script_mandatory_keys("qnap/qts");

  script_tag(name:"summary", value:"QNAP QTS is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"If exploited, these two command injection vulnerabilities could
  allow remote attackers to execute arbitrary commands.");

  script_tag(name:"affected", value:"QNAP QTS prior to version 4.4.3.1421 build 20200907");

  script_tag(name:"solution", value:"Update to version 4.4.3.1421 build 20200907 or later.");

  script_xref(name:"URL", value:"https://www.qnap.com/en/security-advisory/qsa-20-09");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_port_from_cpe_prefix(cpe: CPE_PREFIX))
  exit(0);

CPE = infos["cpe"];

if(!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if(version_is_less(version: version, test_version: "4.4.3_20200907")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.4.3_20200907");
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);

# Copyright (C) 2020 Greenbone Networks GmbH
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

CPE = "cpe:/o:wdc:my_cloud_ex2ultra_firmware";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.143397");
  script_version("2020-01-27T07:51:35+0000");
  script_tag(name:"last_modification", value:"2020-01-27 07:51:35 +0000 (Mon, 27 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-27 07:36:08 +0000 (Mon, 27 Jan 2020)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2019-18929", "CVE-2019-18930", "CVE-2019-18931");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"NoneAvailable");

  script_name("Western Digital My Cloud EX2 Ultra <= 2.31.204 Multiple Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_wd_mycloud_consolidation.nasl");
  script_mandatory_keys("wd-mycloud/detected");

  script_tag(name:"summary", value:"Western Digital My Cloud EX2 Ultra is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Western Digital My Cloud EX2 Ultra is prone to multiple vulnerabilities:

  - Multiple authenticated RCE via stack-based buffer overflows in download_mgr.cgi (CVE-2019-18929, CVE-2019-18930)

  - Buffer Overflow with Extended Instruction Pointer (EIP) control via crafted GET/POST parameters (CVE-2019-18931)");

  script_tag(name:"affected", value:"Western Digital My Cloud EX2 Ultra firmware 2.31.204 and prior.");

  script_tag(name:"solution", value:"No known solution is available as of 27th January, 2020.
  Information regarding this issue will be updated once solution details are available.");

  script_xref(name:"URL", value:"https://github.com/DelspoN/CVE/tree/master/CVE-2019-18929");
  script_xref(name:"URL", value:"https://github.com/DelspoN/CVE/tree/master/CVE-2019-18930");
  script_xref(name:"URL", value:"https://github.com/DelspoN/CVE/tree/master/CVE-2019-18931");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version_is_less_equal(version: version, test_version: "2.31.204")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "None");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

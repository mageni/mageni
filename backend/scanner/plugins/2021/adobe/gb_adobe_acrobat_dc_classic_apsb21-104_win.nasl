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

CPE = "cpe:/a:adobe:acrobat_dc_classic";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818818");
  script_version("2021-10-28T14:01:13+0000");
  script_cve_id("CVE-2021-40728", "CVE-2021-40729", "CVE-2021-40730", "CVE-2021-40731");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-10-29 11:15:42 +0000 (Fri, 29 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-21 21:14:00 +0000 (Thu, 21 Oct 2021)");
  script_tag(name:"creation_date", value:"2021-09-16 13:01:06 +0530 (Thu, 16 Sep 2021)");
  script_name("Adobe Acrobat Classic 2020 Security Update (APSB21-104) - Windows");

  script_tag(name:"summary", value:"Adobe Acrobat is prone to multiple
  code execution and privilege escalation vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to:

  - Multiple use-after-free errors.

  - An out-of-bounds read error.

  - An out-of-bounds write error.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and escalate privileges on a vulnerable system.");

  script_tag(name:"affected", value:"Adobe Acrobat Classic 2020 prior to version
  2020.004.30017 on Windows.");

  script_tag(name:"solution", value:"Update Adobe Acrobat Classic 2020 to
  version 2020.004.30017 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://helpx.adobe.com/security/products/acrobat/apsb21-104.html");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_adobe_acrobat_dc_classic_detect_win.nasl");
  script_mandatory_keys("Adobe/AcrobatDC/Classic/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_in_range(version:vers, test_version:"20.0", test_version2:"20.004.30015"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"20.004.30017(2020.004.30017)", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

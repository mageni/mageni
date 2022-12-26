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

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821324");
  script_version("2022-12-15T10:11:09+0000");
  script_cve_id("CVE-2022-44708", "CVE-2022-4195", "CVE-2022-4194", "CVE-2022-4193",
                "CVE-2022-4192", "CVE-2022-4191", "CVE-2022-4190", "CVE-2022-4189",
                "CVE-2022-4188", "CVE-2022-4187", "CVE-2022-4186", "CVE-2022-4185",
                "CVE-2022-4184", "CVE-2022-4183", "CVE-2022-4182", "CVE-2022-4181",
                "CVE-2022-4180", "CVE-2022-4179", "CVE-2022-4178", "CVE-2022-4177",
                "CVE-2022-4175", "CVE-2022-4174", "CVE-2022-41115");
  script_tag(name:"cvss_base", value:"6.7");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-12-15 10:11:09 +0000 (Thu, 15 Dec 2022)");
  script_tag(name:"creation_date", value:"2022-12-14 14:02:18 +0530 (Wed, 14 Dec 2022)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (December 2022)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) update.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - Use after free in Skia.

  - Heap buffer overflow in WebSQL.

  - Inappropriate implementation in Custom Tabs

  - Use after free in Safe Browsing

  - Use after free in Peer Connection.");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers
  to execute arbitrary code and leak memory on an affected system.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 108.0.5359.71.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"108.0.5359.71"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"108.0.5359.71", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

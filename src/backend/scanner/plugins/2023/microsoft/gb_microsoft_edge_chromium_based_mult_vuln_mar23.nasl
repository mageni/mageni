# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.832029");
  script_version("2023-03-16T10:09:04+0000");
  script_cve_id("CVE-2023-1213", "CVE-2023-1214", "CVE-2023-1215", "CVE-2023-1216",
                "CVE-2023-1217", "CVE-2023-1218", "CVE-2023-1219", "CVE-2023-1220",
                "CVE-2023-1221", "CVE-2023-1222", "CVE-2023-1223", "CVE-2023-1224",
                "CVE-2023-1228", "CVE-2023-1229", "CVE-2023-1230", "CVE-2023-1231",
                "CVE-2023-1232", "CVE-2023-1234", "CVE-2023-1235", "CVE-2023-24892",
                "CVE-2023-1233", "CVE-2023-1236");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:P/A:N");
  script_tag(name:"last_modification", value:"2023-03-16 10:09:04 +0000 (Thu, 16 Mar 2023)");
  script_tag(name:"creation_date", value:"2023-03-15 09:32:56 +0530 (Wed, 15 Mar 2023)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities (March 2023)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Multiple Heap buffer overflow vulnerabilities.

  - A spoofing vulnerability.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to cause heap buffer overflow and conduct spoofing attack.");

  script_tag(name:"affected", value:"Microsoft Edge (Chromium-Based) prior to version 111.0.1661.41.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://learn.microsoft.com/en-us/DeployEdge/microsoft-edge-relnotes-security");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
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

if(version_is_less(version:vers, test_version:"111.0.1661.41"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"111.0.1661.41", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

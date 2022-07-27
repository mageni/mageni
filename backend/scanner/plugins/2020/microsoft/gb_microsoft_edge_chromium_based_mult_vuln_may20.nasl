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

CPE = "cpe:/a:microsoft:edge_chromium_based";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817136");
  script_version("2020-06-02T06:55:43+0000");
  script_cve_id("CVE-2020-6465", "CVE-2020-6466", "CVE-2020-6467", "CVE-2020-6468",
                "CVE-2020-6469", "CVE-2020-6470", "CVE-2020-6471", "CVE-2020-6472",
                "CVE-2020-6473", "CVE-2020-6474", "CVE-2020-6475", "CVE-2020-6476",
                "CVE-2020-6478", "CVE-2020-6479", "CVE-2020-6480", "CVE-2020-6481",
                "CVE-2020-6482", "CVE-2020-6483", "CVE-2020-6484", "CVE-2020-6486",
                "CVE-2020-6487", "CVE-2020-6488", "CVE-2020-6489", "CVE-2020-6490",
                "CVE-2020-1195");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-02 09:39:52 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-05-27 12:17:09 +0530 (Wed, 27 May 2020)");
  script_name("Microsoft Edge (Chromium-Based) Multiple Vulnerabilities - May20");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Edge (Chromium-Based) updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error when the Feedback extension improperly validates input.

  - Missing publicly disclosed security updates from the Chromium project.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to write files to arbitrary locations, gain elevated privileges, escape sandbox,
  execute arbitrary code, inject arbitrary scripts or HTML code, gain access to
  sensitive information, spoof security UI, bypass security restrictions and perform
  domain spoofing.");

  script_tag(name:"affected", value:"- Microsoft Edge (Chromium-Based) prior to version 83.0.478.37");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200002");
  script_xref(name:"URL", value:"https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/CVE-2020-1195");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_microsoft_edge_chromium_based_detect_win.nasl");
  script_mandatory_keys("microsoft_edge_chromium/installed", "microsoft_edge_chromium/ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
edgeVer = infos['version'];
path = infos['location'];

if(version_is_less(version:edgeVer, test_version:"83.0.478.37"))
{
  report = report_fixed_ver(installed_version:edgeVer, fixed_version:"83.0.478.37", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

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

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818510");
  script_version("2021-09-24T05:06:20+0000");
  script_cve_id("CVE-2021-38494", "CVE-2021-38491", "CVE-2021-38492", "CVE-2021-38493");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-09-24 11:43:38 +0000 (Fri, 24 Sep 2021)");
  script_tag(name:"creation_date", value:"2021-09-09 00:46:50 +0530 (Thu, 09 Sep 2021)");
  script_name("Mozilla Firefox Security Update(mfsa_2021-31_2021-42) - Windows");

  script_tag(name:"summary", value:"This host is missing a security update
  according to Mozilla.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws are due to,

  - Mixed-Content-Blocking was unable to check opaque origins.

  - Navigating to 'mk:' URL scheme could load Internet Explorer.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code and bypass security restrictions.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  92 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 92
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2021-38/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"92"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"92", install_path:path);
  security_message(data:report);
  exit(0);
}
exit(99);

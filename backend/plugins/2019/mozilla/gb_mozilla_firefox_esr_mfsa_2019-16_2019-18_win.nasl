# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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


CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815223");
  script_version("2019-06-20T06:01:12+0000");
  script_cve_id("CVE-2019-11707");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-06-20 06:01:12 +0000 (Thu, 20 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-19 10:44:45 +0530 (Wed, 19 Jun 2019)");
  script_name("Mozilla Firefox ESR Security Update (mfsa_2019-16_2019-18)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox ESR
  and is prone to a type confusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists due to a type confusion error
  in Array.pop");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to crash the application and launch further attacks.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before
  60.7.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 60.7.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-18/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/organizations/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox-ESR/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"60.7.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"60.7.1", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(99);

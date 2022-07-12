# Copyright (C) 2020 Greenbone Networks GmbH
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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815885");
  script_version("2020-01-09T13:20:19+0000");
  script_cve_id("CVE-2019-17026");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-01-09 13:20:19 +0000 (Thu, 09 Jan 2020)");
  script_tag(name:"creation_date", value:"2020-01-09 11:26:20 +0530 (Thu, 09 Jan 2020)");
  script_name("Mozilla Firefox Security Updates(mfsa_2020-03_2020-03)-Windows");

  script_tag(name:"summary", value:"This host is installed with Mozilla Firefox
  and is prone to type confusion vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to an incorrect alias
  information in IonMonkey JIT compiler for setting array elements.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers
  to execute arbitrary code in the context of the user running the affected
  applications. Failed exploit attempts will likely cause a denial-of-service
  condition.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  72.0.1 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 72.0.1
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-03/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe:CPE, exit_no_version:TRUE)) exit(0);
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"72.0.1"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"72.0.1", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(0);

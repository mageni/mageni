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


CPE = "cpe:/a:mozilla:firefox";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815264");
  script_version("2019-07-30T06:12:43+0000");
  script_cve_id("CVE-2019-11702");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-07-30 06:12:43 +0000 (Tue, 30 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-25 14:14:29 +0530 (Thu, 25 Jul 2019)");
  script_name("Mozilla Firefox Security Update(mfsa_2019-16_2019-16)-Windows");

  script_tag(name:"summary", value:"This host is installed with
  Mozilla Firefox and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on
  the target host.");

  script_tag(name:"insight", value:"The flaw exists in a hyperlink using protocols
  associated with Internet Explorer such as 'IE.HTTP:'");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to open local files at a known location with Internet Explorer.");

  script_tag(name:"affected", value:"Mozilla Firefox version before
  67.0.2 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox version 67.0.2
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2019-16/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/new/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_firefox_detect_win.nasl");
  script_mandatory_keys("Firefox/Win/Ver");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"67.0.2"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"67.0.2", install_path:ffPath);
  security_message(data:report);
  exit(0);
}
exit(99);

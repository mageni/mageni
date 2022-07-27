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

CPE = "cpe:/a:mozilla:firefox_esr";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817213");
  script_version("2020-07-03T04:20:43+0000");
  script_cve_id("CVE-2020-12417", "CVE-2020-12418", "CVE-2020-12419", "CVE-2020-12420",
                "CVE-2020-12421");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-07-03 10:14:24 +0000 (Fri, 03 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-02 11:52:59 +0530 (Thu, 02 Jul 2020)");
  script_name("Mozilla Firefox ESR Security Updates (MacOSX)-June 30 2020 ");

  script_tag(name:"summary", value:"This host is installed with Mozilla
  Firefox ESR and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Memory corruption due to missing sign-extension for ValueTags on ARM64.

  - Information disclosure due to manipulated URL object.

  - Use-after-free in nsGlobalWindowInner.

  - Use-After-Free when trying to connect to a STUN server.

  - Add-On updates did not respect the same certificate trust rules as software updates.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to conduct a denial-of-service or out-of-bounds read on affected system.");

  script_tag(name:"affected", value:"Mozilla Firefox ESR version before 68.10 on MacOSX.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Firefox ESR version 68.10
  or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-25/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Mozilla/Firefox-ESR/MacOSX/Version");
  exit(0);
}


include("host_details.inc");
include("version_func.inc");

infos = "";
ffVer = "";
ffPath = "";

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE) ) exit( 0 );
ffVer = infos['version'];
ffPath = infos['location'];

if(version_is_less(version:ffVer, test_version:"68.10"))
{
  report = report_fixed_ver(installed_version:ffVer, fixed_version:"68.10", install_path:ffPath);
  security_message(data:report);
  exit(0);
}

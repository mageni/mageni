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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.826756");
  script_version("2023-01-11T10:12:37+0000");
  script_cve_id("CVE-2020-12418", "CVE-2020-12419", "CVE-2020-12420", "CVE-2020-15646",
                "CVE-2020-12421");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-11 10:12:37 +0000 (Wed, 11 Jan 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-07-27 02:15:00 +0000 (Mon, 27 Jul 2020)");
  script_tag(name:"creation_date", value:"2023-01-10 15:43:23 +0530 (Tue, 10 Jan 2023)");
  script_name("Mozilla Thunderbird Security Update(mfsa_2020-26) - Mac OS X");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Information disclosure due to manipulated URL object.

  - Use-after-free in nsGlobalWindowInner.

  - Use-After-Free when trying to connect to a STUN server.

  - Automatic account setup leaks Microsoft Exchange login credentials.

  - Add-On updates did not respect the same certificate trust rules as software updates.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  disclose sensitive information, execute arbitrary code and cause denial of service
  condition.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  68.10.0 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 68.10.0
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2020-26/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_mozilla_prdts_detect_macosx.nasl");
  script_mandatory_keys("Thunderbird/MacOSX/Version");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
tbVer = infos['version'];
tbPath = infos['location'];

if(version_is_less(version:tbVer, test_version:"68.10.0"))
{
  report = report_fixed_ver(installed_version:tbVer, fixed_version:"68.10.0", install_path:tbPath);
  security_message(data:report);
  exit(0);
}

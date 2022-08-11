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

CPE = "cpe:/a:mozilla:thunderbird";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821149");
  script_version("2022-07-14T06:41:19+0000");
  script_cve_id("CVE-2022-1097", "CVE-2022-28281", "CVE-2022-1197", "CVE-2022-1196",
                "CVE-2022-28282", "CVE-2022-28285", "CVE-2022-28286", "CVE-2022-24713",
                "CVE-2022-28289");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-07-14 06:41:19 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-07 22:22:19 +0530 (Thu, 07 Jul 2022)");
  script_name("Mozilla Thunderbird Security Updates(mfsa2022-15) - Windows");

  script_tag(name:"summary", value:"Mozilla Thunderbird is prone to multiple
  vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - Use-after-free in NSSToken objects.

  - Out of bounds write due to unexpected WebAuthN Extensions.

  - OpenPGP revocation information was ignored.

  - Use-after-free after VR Process destruction.

  - Use-after-free in DocumentL10n::TranslateDocument.

  - Incorrect AliasSet used in JIT Codegen.

  - iframe contents could be rendered outside the border.

  - Denial of Service via complex regular expressions.

  - Memory safety bugs.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to run arbitrary code, bypass security restrictions, conduct spoofing
  and cause a denial of service on affected system.");

  script_tag(name:"affected", value:"Mozilla Thunderbird version before
  91.8 on Windows.");

  script_tag(name:"solution", value:"Upgrade to Mozilla Thunderbird version 91.8
  or later, Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2022-15");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_thunderbird_detect_win.nasl");
  script_mandatory_keys("Thunderbird/Win/Ver");
  exit(0);
}
include("host_details.inc");
include("version_func.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
vers = infos['version'];
path = infos['location'];

if(version_is_less(version:vers, test_version:"91.8"))
{
  report = report_fixed_ver(installed_version:vers, fixed_version:"91.8", install_path:path);
  security_message(data:report);
  exit(0);
}

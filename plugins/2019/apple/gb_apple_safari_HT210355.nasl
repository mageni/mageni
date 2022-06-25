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
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA

CPE = "cpe:/a:apple:safari";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815260");
  script_version("2019-07-23T12:43:26+0000");
  script_cve_id("CVE-2019-8670", "CVE-2019-8658", "CVE-2019-8690", "CVE-2019-8644",
                "CVE-2019-8666", "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672",
                "CVE-2019-8673", "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678",
                "CVE-2019-8679", "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683",
                "CVE-2019-8684", "CVE-2019-8685", "CVE-2019-8686", "CVE-2019-8687",
                "CVE-2019-8688", "CVE-2019-8689", "CVE-2019-8649");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-23 12:43:26 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-23 10:36:16 +0530 (Tue, 23 Jul 2019)");
  script_name("Apple Safari Security Updates (HT210355)");

  script_tag(name:"summary", value:"This host is installed with Apple iTunes
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is
  present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An inconsistent user interface issue.

  - Multiple memory corruption issues.

  - Multiple logic issues in the handling of synchronous page loads and document loads.");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers
  to execute arbitrary code, conduct cross site scripting or address bar spoofing
  attacks.");

  script_tag(name:"affected", value:"Apple Safari versions before 12.1.2");

  script_tag(name:"solution", value:"Upgrade to Apple Safari 12.1.2 or later. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210355");
  script_xref(name:"URL", value:"https://support.apple.com/downloads/safari");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("macosx_safari_detect.nasl");
  script_mandatory_keys("AppleSafari/MacOSX/Version");
  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! infos = get_app_version_and_location( cpe:CPE, exit_no_version:TRUE ) ) exit( 0 );
safVer = infos['version'];
safPath = infos['location'];

if(version_is_less(version:safVer, test_version:"12.1.2"))
{
  report = report_fixed_ver(installed_version:safVer, fixed_version:"12.1.2", install_path:safPath);
  security_message(data:report);
  exit(0);
}
exit(99);

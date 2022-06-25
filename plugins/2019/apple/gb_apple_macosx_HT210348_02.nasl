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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815426");
  script_version("2019-07-23T12:43:26+0000");
  script_cve_id("CVE-2019-8649", "CVE-2019-8648", "CVE-2019-8663", "CVE-2019-8661",
                "CVE-2019-8660", "CVE-2019-8667", "CVE-2019-8644", "CVE-2019-8666",
                "CVE-2019-8669", "CVE-2019-8671", "CVE-2019-8672", "CVE-2019-8673",
                "CVE-2019-8676", "CVE-2019-8677", "CVE-2019-8678", "CVE-2019-8679",
                "CVE-2019-8680", "CVE-2019-8681", "CVE-2019-8683", "CVE-2019-8684",
                "CVE-2019-8685", "CVE-2019-8686", "CVE-2019-8687", "CVE-2019-8688",
                "CVE-2019-8689", "CVE-2019-8693", "CVE-2019-8690", "CVE-2019-8694",
                "CVE-2019-8695", "CVE-2019-8646", "CVE-2019-8670", "CVE-2019-8658",
                "CVE-2019-8697");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-07-23 12:43:26 +0000 (Tue, 23 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-23 12:39:20 +0530 (Tue, 23 Jul 2019)");
  script_name("Apple MacOSX Security Updates(HT210348)-02");

  script_tag(name:"summary", value:"This host is installed with Apple Mac OS X
  and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - A logic issue existed in the handling of synchronous page loads.

  - A memory corruption issue due to improper input validation.

  - A use after free issue due to improper memory management.

  - An inconsistent user interface issue due to improper state management.

  - Multiple memory corruption issues due to improper memory handling.

  - A validation issue was addressed with insufficient input sanitization.

  - A logic issue existed in the handling of document loads.

  - An out-of-bounds read error due to improper input validation.

  - A logic issue due to improper state management.");

  script_tag(name:"impact", value:"Successful exploitation allow attackers to
  cause arbitrary code execution, conduct cross site scripting, spoofing attacks,
  leak sensitive information and cause unexpected application termination.");

  script_tag(name:"affected", value:"Apple Mac OS X versions 10.14.x through 10.14.5");

  script_tag(name:"solution", value:"Upgrade to Apple Mac OS X 10.14.6 or later.
  Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");
  script_xref(name:"URL", value:"https://support.apple.com/en-us/HT210348");
  script_xref(name:"URL", value:"https://www.apple.com/in/macos/");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/osx_name", "ssh/login/osx_version");
  exit(0);
}

include("version_func.inc");
include("ssh_func.inc");

osName = get_kb_item("ssh/login/osx_name");
if(!osName){
  exit (0);
}

osVer = get_kb_item("ssh/login/osx_version");
if(!osVer || osVer !~ "^10\.14" || "Mac OS X" >!< osName){
  exit(0);
}

if(osVer =~ "^10\.14")
{
  if(version_is_less(version:osVer, test_version:"10.14.6"))
  {
    report = report_fixed_ver(installed_version:osVer, fixed_version:"10.14.6");
    security_message(data:report);
    exit(0);
  }
}
exit(0);


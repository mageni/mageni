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


if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.821350");
  script_version("2023-01-12T10:12:15+0000");
  script_cve_id("CVE-2023-21734", "CVE-2023-21735");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2023-01-12 10:12:15 +0000 (Thu, 12 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-11 12:55:08 +0530 (Wed, 11 Jan 2023)");
  script_name("Microsoft Office Outlook 2019 RCE Vulnerabilities January-23 (Mac OS X)");

  script_tag(name:"summary", value:"This host is missing an important security
  update for Microsoft Office Outlook 2019 on Mac OSX according to Microsoft
  security update January 2023");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to an unspecified error
  in Microsoft Office Outlook and Graphics");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to trust a signed email message as if it came from a legitimate user and
  execute the code");

  script_tag(name:"affected", value:"Microsoft Office 2019 on Mac OS X.");

  script_tag(name:"solution", value:"Upgrade to version 16.69 (Build 23010700)
  for Microsoft Office 2019. Please see the references for more information.");

  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-gb/officeupdates/release-notes-office-for-mac");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Mac OS X Local Security Checks");
  script_dependencies("gb_microsoft_office_detect_macosx.nasl");
  script_mandatory_keys("MS/Office/MacOSX/Ver");
  exit(0);
}
include("version_func.inc");

if(!vers = get_kb_item("MS/Office/MacOSX/Ver")){
  exit(0);
}

if(vers =~ "^16\.")
{
  if(version_in_range(version:vers, test_version:"16.17.0", test_version2:"16.68")) {
    report = report_fixed_ver(installed_version:vers, fixed_version:"16.69 (Build 23010700)");
    security_message(port:0, data:report);
    exit(0);
  }
}

exit(99);

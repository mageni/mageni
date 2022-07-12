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
  script_oid("1.3.6.1.4.1.25623.1.0.815196");
  script_version("2019-08-14T14:30:23+0000");
  script_cve_id("CVE-2019-1199", "CVE-2019-1204", "CVE-2019-1200", "CVE-2019-1205",
                "CVE-2019-1201", "CVE-2019-1155");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-08-14 14:30:23 +0000 (Wed, 14 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-14 11:52:30 +0530 (Wed, 14 Aug 2019)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-Aug19");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - Multiple errors in Microsoft Outlook when the software fails to properly handle
    objects in memory.

  - An error when Microsoft Outlook initiates processing of incoming messages
    without sufficient validation of the formatting of the messages.

  - Multiple errors in Microsoft Word software when it fails to properly handle objects
    in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to arbitrary code in the context of the current user, force Outlook to load a
  local or remote message store and perform actions in the security context of the
  current user");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run)");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_office_click2run_detect_win.nasl");
  script_mandatory_keys("MS/Off/C2R/Ver", "MS/Office/C2R/UpdateChannel");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

officeVer = get_kb_item("MS/Off/C2R/Ver");
if(!officeVer || officeVer !~ "^16\."){
  exit(0);
}

UpdateChannel = get_kb_item("MS/Office/C2R/UpdateChannel");
officePath = get_kb_item("MS/Off/C2R/InstallPath");

## 1907 (Build 11901.20218)
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11901.20218")){
    fix = "1907 (Build 11901.20218)";
  }
}

## 1902 (Build 11328.20392)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11328.20392")){
    fix = "1902 (Build 11328.20392)";
  }
}

## 1902 (Build 11328.20392)
## 1808 (Build 10730.20370)
## 1803 (Build 9126.2432)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.9126.2432")){
    fix = "1803 (Build 9126.2432)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.10730", test_version2:"16.0.10730.20369")){
    fix = "1808 (Build 10730.20370)";
  }
  else if(version_in_range(version:officeVer, test_version:"16.0.11328", test_version2:"16.0.11328.20391")){
    fix = "1902 (Build 11328.20392)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);

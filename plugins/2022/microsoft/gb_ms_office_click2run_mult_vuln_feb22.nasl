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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.818969");
  script_version("2022-02-09T15:13:32+0000");
  script_cve_id("CVE-2022-22716", "CVE-2022-21988", "CVE-2022-22003", "CVE-2022-23252",
                "CVE-2022-22004");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-10 11:02:19 +0000 (Thu, 10 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-09 06:00:50 +0530 (Wed, 09 Feb 2022)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities - Feb22");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Office Click-to-Run updates");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to:

  - An information disclosure vulnerability in Microsoft Excel.

  - A remote code execution vulnerability in Microsoft Office Visio.

  - A remote code execution vulnerability in Microsoft Office Graphics.

  - An information disclosure vulnerability in Microsoft Office.

  - A remote code execution vulnerability in Microsoft Office ClickToRun.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to conduct remote code execution and gain access to sensitive information.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");

  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/microsoft365-apps-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
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

## Version 2201 (Build 14827.20192)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14827.20192")){
    fix = "2201 (Build 14827.20192)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Semi-Annual Enterprise Channel (Preview): Version 2108 (Build 14326.20784)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.14326.20784")){
    fix = "2108 (Build 14326.20784)";
  }
}

## Semi-Annual Enterprise Channel: Version 2108 (Build 14326.20784)
## Semi-Annual Enterprise Channel: Version 2102 (Build 13801.21156)
## Semi-Annual Enterprise Channel: Version 2008 (Build 13127.21886)
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.21886")){
    fix = "2008 (Build 13127.21886)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.13801", test_version2:"16.0.13801.21155")){
    fix = "2102 (Build 13801.21156)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.14326", test_version2:"16.0.14326.20783")){
    fix = "2108 (Build 14326.20784)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);

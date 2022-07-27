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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.817399");
  script_version("2020-10-14T15:29:30+0000");
  script_cve_id("CVE-2020-16957", "CVE-2020-16929", "CVE-2020-16931", "CVE-2020-16932",
                "CVE-2020-16947", "CVE-2020-16949", "CVE-2020-16933", "CVE-2020-16930",
                "CVE-2020-16955", "CVE-2020-16928", "CVE-2020-16934", "CVE-2020-16918",
                "CVE-2020-16954");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2020-10-15 11:08:37 +0000 (Thu, 15 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-14 08:37:56 +0530 (Wed, 14 Oct 2020)");
  script_name("Microsoft Office 365 (2016 Click-to-Run) Multiple Vulnerabilities-Oct20");

  script_tag(name:"summary", value:"This host is missing a critical security
  update according to Microsoft Office Click-to-Run updates.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present
  on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exist due to,

  - An error when the Microsoft Office Access Connectivity Engine improperly
    handles objects in memory.

  - Multiple errors in Microsoft Excel software when the software fails to properly
    handle objects in memory.

  - Multiple errors in Microsoft Outlook software when the software fails to
    properly handle objects in memory.

  - An error in Microsoft Word software when it fails to properly handle .LNK files.

  - Multiple errors in the way that Microsoft Office Click-to-Run (C2R) AppVLP handles
    certain files.

  - An error when the Base3D rendering engine improperly handles memory.

  - An error in Microsoft Office software when the software fails to properly handle
    objects in memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to execute arbitrary code, gain elevated privileges, bypass security restrictions
  and conduct a denial-of-service condition.");

  script_tag(name:"affected", value:"Microsoft Office 365 (2016 Click-to-Run).");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released updates. Please see
  the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/officeupdates/office365-proplus-security-updates");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
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

## Version 2009 (Build 13231.20390)
## Monthly Channel renamed to Current Channel
if(UpdateChannel == "Monthly Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13231.20390")){
    fix = "2009 (Build 13231.20390)";
  }
}

## Semi-Annual Channel (Targeted) renamed to Semi-Annual Enterprise Channel (Preview)
## Version 2008 (Build 13127.20638)
else if(UpdateChannel == "Semi-Annual Channel (Targeted)")
{
  if(version_is_less(version:officeVer, test_version:"16.0.13127.20638")){
    fix = "2008 (Build 13127.20638)";
  }
}

## Version 2002 (Build 12527.21236)
## Version 1908 (Build 11929.20966)
## Semi-Annual Channel renamed to Semi-Annual Enterprise Channel
else if(UpdateChannel == "Semi-Annual Channel")
{
  if(version_is_less(version:officeVer, test_version:"16.0.11929.20966")){
    fix = "1908 (Build 11929.20966)";
  }

  else if(version_in_range(version:officeVer, test_version:"16.0.12527", test_version2:"16.0.12527.21236")){
    fix = "2002 (Build 12527.21236)";
  }
}

if(fix)
{
  report = report_fixed_ver(installed_version:officeVer, fixed_version:fix, install_path:officePath);
  security_message(data:report);
  exit(0);
}
exit(99);

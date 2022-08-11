###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft PowerPoint Viewer 2007 Remote Code Execution Vulnerability (KB2597975)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.814538");
  script_version("2019-05-03T08:55:39+0000");
  script_cve_id("CVE-2018-8628");
  script_bugtraq_id(106104);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 08:55:39 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-12-12 14:11:59 +0530 (Wed, 12 Dec 2018)");
  script_name("Microsoft PowerPoint Viewer 2007 Remote Code Execution Vulnerability (KB2597975)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB2597975");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists in Microsoft PowerPoint Viewer
  when the software fails to properly handle objects in Protected View.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to run arbitrary code in the context of the current user.");

  script_tag(name:"affected", value:"Microsoft PowerPoint Viewer 2007");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/2597975");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("MS/Office/Ver", "SMB/Office/PPView/Version");
  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

ppviewVer = get_kb_item("SMB/Office/PPView/Version");
if(!ppviewVer){
  exit(0);
}

ppviewPath =  get_kb_item("SMB/Office/PPView/FilePath");
if(!ppviewPath){
  ppviewPath = "Unable to get installation path";
}

if(ppviewVer =~ "^12\." && version_is_less(version:ppviewVer, test_version:"12.0.6805.5000"))
{
  report = report_fixed_ver(file_checked:ppviewPath + "\pptview.exe",
                            file_version:ppviewVer, vulnerable_range:"12.0 - 12.0.6805.4999");
  security_message(data:report);
}
exit(99);

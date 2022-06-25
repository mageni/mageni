###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Word 2013 Service Pack 1 Information Disclosure Vulnerability (KB4018347)
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
  script_oid("1.3.6.1.4.1.25623.1.0.812591");
  script_version("2019-05-03T10:12:14+0000");
  script_cve_id("CVE-2018-0950");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:12:14 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2018-04-11 10:33:34 +0530 (Wed, 11 Apr 2018)");
  script_name("Microsoft Word 2013 Service Pack 1 Information Disclosure Vulnerability (KB4018347)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft KB4018347");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw exists when Office renders Rich
  Text Format (RTF) email messages containing OLE objects while a message is
  opened or previewed.");

  script_tag(name:"impact", value:"Successful exploitation will allow an attacker
  to gain access to potentially sensitive information.");

  script_tag(name:"affected", value:"Microsoft Word 2013 Service Pack 1");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"executable_version");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/4018347");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_mandatory_keys("SMB/Office/Word/Version");

  exit(0);
}


include("smb_nt.inc");
include("host_details.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

exeVer = get_kb_item("SMB/Office/Word/Version");
if(!exeVer){
  exit(0);
}

exePath = get_kb_item("SMB/Office/Word/Install/Path");
if(!exePath){
  exePath = "Unable to fetch the install path";
}

if(exeVer =~ "^(15\.)" && version_is_less(version:exeVer, test_version:"15.0.5023.1000"))
{
  report = report_fixed_ver(file_checked: exePath + "winword.exe",
                            file_version:exeVer, vulnerable_range:"15.0 - 15.0.5023.0999");
  security_message(data:report);
}
exit(0);

###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Office Remote Code Execution Vulnerability (3017349)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805022");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-6364");
  script_bugtraq_id(71474);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-12-10 09:17:13 +0530 (Wed, 10 Dec 2014)");
  script_name("Microsoft Office Remote Code Execution Vulnerability (3017349)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-082.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"The flaw is due to a use-after-free error
  and can be exploited to corrupt memory.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to execute arbitrary code on the affected system.");

  script_tag(name:"affected", value:"Microsoft Office 2007 Service Pack 3 and prior

  Microsoft Office 2010 Service Pack 2 and prior

  Microsoft Office 2013 Service Pack 1 and prior.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://secunia.com/advisories/61150");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/3017349");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-082");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_office_products_version_900032.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/Office/Ver");

  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms14-082");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

officeVer = get_kb_item("MS/Office/Ver");

## MS Office 2007/2010/2013
if(!officeVer || officeVer !~ "^1[245]\."){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath ){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"system32\fm20.dll");
if(!dllVer){
  exit(0);
}

if(version_in_range(version:dllVer, test_version:"14.0", test_version2:"14.0.7140.5000") ||
   version_in_range(version:dllVer, test_version:"12.0", test_version2:"12.0.6713.4999") ||
   version_in_range(version:dllVer, test_version:"15.0", test_version2:"15.0.4675.1000"))
{
  security_message( port: 0, data: "The target host was found to be vulnerable" );
  exit(0);
}

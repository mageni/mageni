###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Visio Information Disclosure Vulnerability (2834692)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2013 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902967");
  script_version("2019-05-21T06:50:08+0000");
  script_cve_id("CVE-2013-1301");
  script_bugtraq_id(59765);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-21 06:50:08 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2013-03-13 13:32:19 +0530 (Wed, 13 Mar 2013)");
  script_name("Microsoft Visio Information Disclosure Vulnerability (2834692)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/53380");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2810062");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2596595");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/2810068");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/security/bulletin/ms13-044");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"impact", value:"Successful exploitation will allow attackers to disclose potentially
  sensitive information.");

  script_tag(name:"affected", value:"Microsoft Visio 2007 Service Pack 3 and prior

  Microsoft Visio 2003 Service Pack 3 and prior

  Microsoft Visio 2010 Service Pack 1 and prior.");

  script_tag(name:"insight", value:"The flaw is due to an error in the application when parsing XML files with
  external entities. This can be exploited to disclose the contents of arbitrary files.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing an important security update according to
  Microsoft Bulletin MS13-044.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                             "\App Paths\visio.exe", item:"Path");
if(!sysPath){
  exit(0);
}

visVer = fetch_file_version(sysPath:sysPath, file_name:"Visbrgr.dll");
if(visVer && visVer =~ "^11\.")
{
  if(version_in_range(version:visVer, test_version:"11.0", test_version2:"11.0.8401.0000"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

exeVer = fetch_file_version(sysPath:sysPath, file_name:"visio.exe");
if(exeVer && exeVer =~ "^1[24]\.")
{
  if(version_in_range(version:exeVer, test_version:"12.0", test_version2:"12.0.6676.4999") ||
     version_in_range(version:exeVer, test_version:"14.0", test_version2:"14.0.7100.4999"))
  {
    security_message( port: 0, data: "The target host was found to be vulnerable" );
    exit(0);
  }
}

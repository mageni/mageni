###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft iSCSI Denial of Service Vulnerabilities (2962485)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802074");
  script_version("2019-05-03T12:31:27+0000");
  script_cve_id("CVE-2014-0255", "CVE-2014-0256");
  script_bugtraq_id(67280, 67281);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-05-14 17:09:23 +0530 (Wed, 14 May 2014)");
  script_tag(name:"solution_type", value:"VendorFix");
  script_name("Microsoft iSCSI Denial of Service Vulnerabilities (2962485)");


  script_tag(name:"summary", value:"This host is missing an important security update according to Microsoft
Bulletin MS14-028.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Flaw is due to an error when handling large amounts of specially crafted
iSCSI packets.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to cause the iSCSI service to
stop responding via specially crafted iSCSI packets.");
  script_tag(name:"affected", value:"Microsoft Windows Server 2012
Microsoft Windows Server 2012 R2
Microsoft Windows Server 2008 R2 x64 Service Pack 1 and prior");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");

  script_xref(name:"URL", value:"http://secunia.com/advisories/58281");
  script_xref(name:"URL", value:"https://support.microsoft.com/kb/2933826");
  script_xref(name:"URL", value:"https://technet.microsoft.com/library/security/ms14-028");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008r2:2, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

sysPath = smb_get_systemroot();
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"\system32\Iscsitgt.dll");
if(!sysVer){
  exit(0);
}

## Presently given info is not clear on Windows 2008 R2
## TODO: Need to add support for Windows 2008 R2 once required details
## are available

if(hotfix_check_sp(win2012:1) > 0)
{
  if(version_in_range(version:sysVer, test_version:"6.2.9200.16000", test_version2:"6.2.9200.16885")||
     version_in_range(version:sysVer, test_version:"6.3.9200.16000", test_version2:"6.3.9600.16659")||
     version_in_range(version:sysVer, test_version:"6.2.9200.21000", test_version2:"6.2.9200.21004")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

if(hotfix_check_sp(win2012R2:1) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.3.9600.17095")){
   security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

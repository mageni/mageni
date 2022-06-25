###############################################################################
# OpenVAS Vulnerability Test
#
# MS Active Directory Federation Services Information Disclosure Vulnerability (3003381)
#
# Authors:
# Thanga Prakash S <tprakash@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.804792");
  script_version("2019-05-03T10:54:50+0000");
  script_cve_id("CVE-2014-6331");
  script_bugtraq_id(70938);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2014-11-12 15:02:25 +0530 (Wed, 12 Nov 2014)");
  script_name("MS Active Directory Federation Services Information Disclosure Vulnerability (3003381)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft Bulletin MS14-077.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerability exists when Active Directory
  Federation Services (AD FS) fails to properly log off a user.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attackers to obtain potentially sensitive information.");

  script_tag(name:"affected", value:"Active Directory Federation Services 2.0
  on Windows Server 2008 x86/x64 sp2, Active Directory Federation Services 2.0
  on Windows Server 2008 R2 sp1, Active Directory Federation Services 2.1 on
  Windows Server 2012, Active Directory Federation Services 3.0 on
  Windows Server 2012 R2.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"registry");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/3003381");
  script_xref(name:"URL", value:"http://technet.microsoft.com/security/bulletin/MS14-077");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2008:3, win2008r2:2, win2012:1, win2012R2:1) <= 0){
  exit(0);
}

adfs1 = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS");
adfs2 = registry_key_exists(key:"SOFTWARE\Microsoft\ADFS2.0");
if(!adfs1 && !adfs2){
  exit(0);
}

ProgramFilesDir = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                                 item:"ProgramFilesDir");
if(ProgramFilesDir)
{
  adfs1_path = ProgramFilesDir + "\Active Directory Federation Services 2.0";

  adfs1_ver = fetch_file_version(sysPath:adfs1_path, file_name:"Microsoft.identityserver.dll");
  if(adfs1_ver)
  {
    if((hotfix_check_sp(win2008:3) > 0) &&
       (version_in_range(version:adfs1_ver, test_version:"6.1.7600.00000", test_version2:"6.1.7601.18621")||
        version_in_range(version:adfs1_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22827")))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }

    if((hotfix_check_sp(win2008r2:2) > 0) &&
       (version_in_range(version:adfs1_ver, test_version:"6.1.7600.00000", test_version2:"6.1.7601.18619")||
        version_in_range(version:adfs1_ver, test_version:"6.1.7601.22000", test_version2:"6.1.7601.22826")))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}


sysPath = smb_get_systemroot();
if(sysPath)
{
  adfs2_ver = fetch_file_version(sysPath:sysPath, file_name:"\ADFS\Microsoft.identityserver.dll");
  if(adfs2_ver)
  {
    if((hotfix_check_sp(win2012:1) > 0) &&
       (version_in_range(version:adfs2_ver, test_version:"6.2.9200.16000", test_version2:"6.2.9200.17134")||
        version_in_range(version:adfs2_ver, test_version:"6.2.9200.20000", test_version2:"6.2.9200.21251")))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }

    if((hotfix_check_sp(win2012R2:1) > 0) &&
       (version_in_range(version:adfs2_ver, test_version:"6.3.9600.17000", test_version2:"6.3.9600.17411")))
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }
  }
}

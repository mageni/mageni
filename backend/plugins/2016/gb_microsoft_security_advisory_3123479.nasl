###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Root Certificate Program SHA-1 Deprecation Advisory (3123479)
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.806663");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2016-01-14 13:09:43 +0530 (Thu, 14 Jan 2016)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Root Certificate Program SHA-1 Deprecation Advisory (3123479)");

  script_tag(name:"summary", value:"This host is missing an important security
  update according to Microsoft advisory (3123479).");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"An update is available that aims to warn
  customers in assessing the risk of certain applications that use X.509 digital
  certificates that are signed using the SHA-1 hashing algorithm.");

  script_tag(name:"impact", value:"Successful exploitation will allow
  attackers to take advantage of weakness of the SHA-1 hashing algorithm that
  exposes it to collision attacks.");

  script_tag(name:"affected", value:"Microsoft Windows 8 x32/x64

  Microsoft Windows 10 x32/x64

  Microsoft Windows 8.1 x32/x64

  Microsoft Windows Server 2012/2012R2

  Microsoft Windows 10 Version 1511 x32/x64.

  Microsoft Windows 7 x32/x64 Edition Service Pack 1

  Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3197869");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3197875");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3198585");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3198586");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/help/3200970");
  script_xref(name:"URL", value:"https://support.microsoft.com/en-us/kb/3123479");
  script_xref(name:"URL", value:"https://technet.microsoft.com/en-us/library/security/3123479");
  script_xref(name:"URL", value:"http://social.technet.microsoft.com/wiki/contents/articles/32288.windows-enforcement-of-authenticode-code-signing-and-timestamping.aspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Windows");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2, win8:1, win8x64:1,
                   win2012:1, win2012R2:1, win8_1:1, win8_1x64:1,
                   win2008:3, win10:1, win10x64:1) <= 0){
  exit(0);
}

## Following KBs already covered: KB3198585, KB3198586,
## KB3200970 in 2016/gb_ms16-129.nasl


## KB3197869, KB3197875
sysPath = smb_get_system32root();
if(!sysPath ){
  exit(0);
}

winVer = fetch_file_version(sysPath:sysPath, file_name:"Win32k.sys");
if(winVer)
{
  ##https://support.microsoft.com/en-in/help/3197875
  if(hotfix_check_sp(win8_1:1, win8_1x64:1, win2012R2:1) > 0)
  {
    if(version_is_less(version:winVer, test_version:"6.3.9600.18524"))
    {
      Vulnerable_range = "Less than 6.3.9600.18524";
      VULN = TRUE ;
    }
  }

  ## https://support.microsoft.com/en-in/help/3197869
  else if(hotfix_check_sp(win7:2, win7x64:2, win2008r2:2) > 0)
  {
    if(version_is_less(version:winVer, test_version:"6.1.7601.23584"))
    {
      Vulnerable_range = "Less than 6.1.7601.23584";
      VULN = TRUE ;
    }
  }

  if(VULN)
  {
     report = 'File checked:     ' + sysPath + "\win32k.sys" + '\n' +
              'File version:     ' + winVer  + '\n' +
              'Vulnerable range: ' + Vulnerable_range + '\n' ;
     security_message(data:report);
     exit(0);
  }
}

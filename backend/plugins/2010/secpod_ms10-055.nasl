###############################################################################
# OpenVAS Vulnerability Test
#
# Remote Code Execution Vulnerability in Cinepak Codec (982665)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-11
#  - To detect file version 'Iccvid.dll' on vista, win 7 os
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900249");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-08-11 15:08:29 +0200 (Wed, 11 Aug 2010)");
  script_bugtraq_id(42256);
  script_cve_id("CVE-2010-2553");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Remote Code Execution Vulnerability in Cinepak Codec (982665)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/40936");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/982665");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS10-055.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code with the privileges of the user running the application.");
  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows Vista service Pack 2 and prior.
  Microsoft Windows 7");
  script_tag(name:"insight", value:"The Cinepak Codec applications fails to perform adequate boundary checks
  while handling supported format files.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-055.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, winVista:3, win7:1) <= 0){
  exit(0);
}
## MS10-050 Hotfix check
if(hotfix_missing(name:"982665") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Iccvid.dll");
  if(!dllVer){
    exit(0);
  }

  if(hotfix_check_sp(xp:4) > 0)
  {
    if(version_is_less(version:dllVer, test_version:"1.10.0.13")){
       security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
        exit(0);
  }
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}

dllVer = fetch_file_version(sysPath:sysPath, file_name:"iccvid.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3, win7:1) > 0)
{
  if(version_is_less(version:dllVer, test_version:"1.10.0.13")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}


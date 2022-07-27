###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Explorer Multiple Vulnerabilities (980182)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-09-19
#    - To detect file version 'iepeers.dll' on vista, win 2008 and win 7 os
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
  script_oid("1.3.6.1.4.1.25623.1.0.902155");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-04-01 11:04:35 +0200 (Thu, 01 Apr 2010)");
  script_cve_id("CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0490",
                "CVE-2010-0491", "CVE-2010-0492", "CVE-2010-0494", "CVE-2010-0805",
                "CVE-2010-0806", "CVE-2010-0807");
  script_bugtraq_id(39023, 39028, 39026, 39031, 39027, 39030, 39047, 39025, 38615, 39024);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Explorer Multiple Vulnerabilities (980182)");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/980182");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2010/0744");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/MS10-018");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_mandatory_keys("MS/IE/Version");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation will let the attacker execute arbitrary codes via
  specially crafted HTML page in the context of the affected system and cause
  memory corruption.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer version 5.x/6.x/7.x/8.x");
  script_tag(name:"insight", value:"The Multiple flaws are due to:

  - An use-after-free error within 'iepeers.dll'.

  - A memory corruption error when the browser accesses certain objects.

  - A memory corruption error when handling certain HTML objects

  - A error when handling content using specific encoding strings while
    submitting data.

  - A memory corruption error when the browser attempts to access an object
    that may have been corrupted due to a race condition.

  - Browser incorrectly interpreting the origin of scripts and HTML elements

  - A memory corruption error within the Tabular Data Control (TDC) ActiveX when
    processing overly long URLs");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-018.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2k:5, win2003:3, winVista:3, win7:1, win2008:3) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS10-018 Hotfix (980182)
if(hotfix_missing(name:"980182") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"Iepeers.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_in_range(version:dllVer, test_version:"5.0", test_version2:"5.0.3886.1899") ||
         version_in_range(version:dllVer, test_version:"6.0", test_version2:"6.0.2800.1645"))
      {
        security_message( port: 0, data: "The target host was found to be vulnerable" );
        exit(0);
      }
    }

    else if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.2900.3675")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17022")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21227")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18903")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22994")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }

      else if("Service Pack 3" >< SP)
      {
        if(version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.2900.5944")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17022")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21227")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18903")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22994")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        # 8.0 <  8.0.6001.18904
        if(version_in_range(version: dllVer, test_version:"6.0.0000.0000", test_version2:"6.0.3790.4671")||
           version_in_range(version: dllVer, test_version:"7.0.0000.00000", test_version2:"7.0.6000.17022")||
           version_in_range(version: dllVer, test_version:"7.0.6000.21000", test_version2:"7.0.6000.21227")||
           version_in_range(version: dllVer, test_version:"8.0.6001.18000", test_version2:"8.0.6001.18903")||
           version_in_range(version: dllVer, test_version:"8.0.6001.23000", test_version2:"8.0.6001.22994")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = smb_get_system32root();
if(!sysPath){
  exit(0);
}
dllVer = fetch_file_version(sysPath:sysPath, file_name:"Ieframe.dll");
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win7:1) > 0)
{
  if(version_in_range(version: dllVer, test_version:"8.0.7600.16000", test_version2:"8.0.7600.16534")||
     version_in_range(version: dllVer, test_version:"8.0.7600.20000", test_version2:"8.0.7600.20650")){
     security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}


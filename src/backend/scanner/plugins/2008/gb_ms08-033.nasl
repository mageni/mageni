###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in DirectX Could Allow Remote Code Execution (951698)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Copyright:
# Copyright (c) 2008 Intevation GmbH, http://www.intevation.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800104");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-30 14:16:17 +0200 (Tue, 30 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-0011", "CVE-2008-1444");
  script_bugtraq_id(29581, 29578);
  script_name("Vulnerabilities in DirectX Could Allow Remote Code Execution (951698)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30579");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/1780");
  script_xref(name:"URL", value:"http://www.us-cert.gov/cas/techalerts/TA08-162B.html");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-08-040/");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-033.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Intevation GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to execute arbitrary code when
  a user opens a specially crafted media file. An attacker could take complete
  control of an affected system.");

  script_tag(name:"affected", value:"DirectX 7.0, 8.1, 9.0, 9.0a, 9.0b and 9.0c on Microsoft Windows 2000

  DirectX 9.0, 9.0a, 9.0b and 9.0c on Microsoft Windows XP and 2003

  DirectX 10.0 on Microsoft Windows Vista and 2008 Server");

  script_tag(name:"insight", value:"The flaws are due to

  - error in the Windows MJPEG Codec when performing error checking on MJPEG
  video streams embedded in ASF or AVI media files which can be exploited
  with a specially crafted MJPEG file.

  - error in the parsing of Class Name variables in Synchronized Accessible
  Media Interchange (SAMI) files which can be exploited with a specially
  crafted SAMI file.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host has DirectX installed, which is prone to remote code
  execution vulnerabilities.");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

dllFile = smb_get_system32root();
if(!dllFile){
  exit(0);
}

dllFile += "\quartz.dll";

directXver = registry_get_sz(key:"SOFTWARE\Microsoft\DirectX", item:"Version");
if(!egrep(pattern:"^4\.0[7-9]\..*", string:directXver)){
  exit(0);
}

# MS08-033 Hotfix check
if(hotfix_missing(name:"951698") == 0){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(egrep(pattern:"^4\.07", string:directXver))
  {
    fileVer = get_version(dllPath:dllFile, string:"prod", offs:600000);
    if(fileVer == NULL){
      exit(0);
    }

    if(egrep(pattern:"^6\.01\.09\.0?([0-6]?[0-9]?[0-9]|7([0-2][0-9]|3[0-3]))$",
             string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else if(egrep(pattern:"^4\.08", string:directXver))
  {
    if(egrep(pattern:"^6\.03\.01\.0?([0-7]?[0-9]?[0-9]|8([0-8][0-9]|90))$",
             string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  else if(egrep(pattern:"^4\.09", string:directXver))
  {
    if(egrep(pattern:"^6\.05\.0?1\.0?([0-8]?[0-9]?[0-9]|90[0-8])$",
             string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    else if(egrep(pattern:"^6\.05\.2600\.(0?[0-9]?[0-9]?[0-9]|1([0-2][0-9]" +
                       "[0-9]|3(0[0-9]|1[0-5])))$", string:fileVer)){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  if(egrep(pattern:"^4\.09", string:directXver))
  {
    fileVer = get_version(dllPath:dllFile, string:"prod", offs:600000);;
    if(fileVer == NULL){
      exit(0);
    }

    SP = get_kb_item("SMB/WinXP/ServicePack");
    if("Service Pack 2" >< SP)
    {
      if(egrep(pattern:"^6\.05\.2600\.([0-2]?[0-9]?[0-9]?[0-9]|3([0-2][0-9]" +
                       "[0-9]|3([0-5][0-9]|6[0-6])))$", string:fileVer)){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
    else if("Service Pack 3" >< SP)
    {
      if(egrep(pattern:"^6\.05\.2600\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-4][0-9]" +
                       "[0-9]|5([0-8][0-9]|9[0-5])))$", string:fileVer)){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
  exit(0);
}

if(hotfix_check_sp(win2003:3) > 0)
{
  if(egrep(pattern:"^4\.09", string:directXver))
  {
    fileVer = get_version(dllPath:dllFile, string:"prod", offs:600000);
    if(fileVer == NULL){
      exit(0);
    }

    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(egrep(pattern:"^6\.05\.3790\.([0-2]?[0-9]?[0-9]?[0-9]|3(0[0-9]" +
                       "[0-9]|1[0-2][0-9]))$", string:fileVer)){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
    else if("Service Pack 2" >< SP)
    {
      if(egrep(pattern:"^6\.05\.3790\.([0-3]?[0-9]?[0-9]?[0-9]|4([01][0-9]" +
                       "[0-9]|2([0-7][0-9]|8[0-2])))$", string:fileVer)){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
    }
  }
}

dllPath = smb_get_system32root();
if(!dllPath){
  exit(0);
}

fileVer =  fetch_file_version(sysPath:dllPath, file_name:"\Quartz.dll");
if(fileVer)
{
  if(hotfix_check_sp(winVista:2) > 0)
  {
    SP = get_kb_item("SMB/WinVista/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(version_is_less(version:fileVer, test_version:"6.6.6001.18063")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
  }

  else if(hotfix_check_sp(win2008:2) > 0)
  {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(version_is_less(version:fileVer, test_version:"6.6.6001.18063")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }
  }
}

##############################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Security Update for Internet Explorer (931768)
#
# LSS-NVT-2010-045
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2010 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102056");
  script_version("2019-05-03T12:31:27+0000");
  script_tag(name:"last_modification", value:"2019-05-03 12:31:27 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-07-08 10:59:30 +0200 (Thu, 08 Jul 2010)");
  script_bugtraq_id(23771, 23769, 23772, 23827);
  script_cve_id("CVE-2007-0942", "CVE-2007-0944", "CVE-2007-0945",
                "CVE-2007-0947", "CVE-2007-2221");
  script_name("Cumulative Security Update for Internet Explorer (931768)");
  script_xref(name:"URL", value:"http://secunia.com/secunia_research/2007-36/");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/Bulletin/MS07-027.mspx");
  script_tag(name:"qod_type", value:"executable_version");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 LSS");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("gb_ms_ie_detect.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("MS/IE/Version");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"Microsoft Internet Explorer 5.01 SP4 on Windows 2000 SP4, 6 SP1 on
  Windows 2000 SP4, 6 and 7 on Windows XP SP2, or Windows Server 2003
  SP1 or SP2, and possibly 7 on Windows Vista does not properly
  instantiate certain COM objects as ActiveX controls, which allows
  remote attackers to execute arbitrary code via a crafted COM object
  from chtskdic.dll.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5 ,xp:4 ,win2003:3 ,vista:3 ) <= 0){
  exit(0);
}

ieVer = get_kb_item("MS/IE/Version");
if(!ieVer){
  exit(0);
}

# MS07-027 Hotfix (931768)
if(hotfix_missing(name:"931768") == 0){
  exit(0);
}
affected=0;

dllPath = registry_get_sz(item:"Install Path", key:"SOFTWARE\Microsoft\COM3\Setup");
dllPath += "\mshtml.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);
vers = GetVer(file:file, share:share);

dllPath = registry_get_sz(item:"Install Path", key:"SOFTWARE\Microsoft\COM3\Setup");
dllPath += "\ieapfltr.dll";
share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:dllPath);

vers2 = GetVer(file:file, share:share);
if(!vers && !vers2){
  exit(0);
}

#CVE-2007-0942, CVE-2007-0944, CVE-2007-0945, CVE-2007-0947, CVE-2007-2221
if(hotfix_check_sp(win2k:5) > 0 && vers)
{
  SP = get_kb_item("SMB/Win2K/ServicePack");
  if("Service Pack 4" >< SP)
  {
    if(version_in_range(version:vers, test_version:"5.0", test_version2:"5.0.3850.1900") ||
       version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1593")){
      security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);
    }
  }
}
else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if((vers && version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.2800.1593")) ||
       (vers && version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4026")) ||
       (vers2 && version_in_range(version:vers2, test_version:"7.0", test_version2:"7.0.6000.16432"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);
    }
  }
}

else if(hotfix_check_sp(win2003:3) > 0)
{
  SP = get_kb_item("SMB/Win2003/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if((vers && version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.2885")) ||
       (vers2 && version_in_range(version:vers2, test_version:"7.0", test_version2:"7.0.6000.16432"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);
    }
  }
  else if("Service Pack 2" >< SP)
  {

    if((vers && version_in_range(version:vers, test_version:"6.0", test_version2:"6.0.3790.4026")) ||
       (vers2 && version_in_range(version:vers2, test_version:"6.0", test_version2:"7.0.6000.16432"))){
      security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);
    }
  }
}

else if(hotfix_check_sp(vista:2) > 0 && vers)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 0" >< SP)
  {
    if(version_in_range(version:vers, test_version:"7.0", test_version2:"7.0.6000.20547")){
      security_message( port: 0, data: "The target host was found to be vulnerable" ); exit(0);
    }
  }
}

exit(99);

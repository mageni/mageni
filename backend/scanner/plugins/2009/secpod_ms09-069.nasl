###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows LSASS Denial of Service Vulnerability (974392)
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901063");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-12-09 16:08:24 +0100 (Wed, 09 Dec 2009)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_cve_id("CVE-2009-3675");
  script_name("Microsoft Windows LSASS Denial of Service Vulnerability (975467)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/37524/");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/974392");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/3433");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/MS09-069.mspx");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to cause a Denial of
  Service on the victim's system.");
  script_tag(name:"affected", value:"Microsoft Windows 2K  Service Pack 4 and prior.
  Microsoft Windows XP  Service Pack 3 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.");
  script_tag(name:"insight", value:"This issue is caused by an error when communicating through Internet Protocol
  security (IPsec), sending a specially crafted ISAKMP message to the Local
  Security Authority Subsystem Service (LSASS) on an affected system.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-069.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms09-069.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3) <= 0){
  exit(0);
}


# MS09-069 Hotfix check
if(hotfix_missing(name:"974392") == 0){
  exit(0);
}

dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(!dllPath){
  exit(0);
}

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:dllPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1",
                    string:dllPath + "\Oakley.dll");

dllVer = GetVer(file:file, share:share);
if(!dllVer){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  if(version_is_less(version:dllVer, test_version:"5.0.2195.7343")){
    security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
}

else if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"5.1.2600.3632")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  else if("Service Pack 3" >< SP)
  {
    if(version_is_less(version:dllVer, test_version:"5.1.2600.5886")){
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
    if(version_is_less(version:dllVer, test_version:"5.2.3790.4600")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

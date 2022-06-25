###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (975561)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-05-04
# Updated according to the Bulletin Revision V2.0 (May 3, 2010).
#
# Updated By: Madhuri D <dmadhuri@secpod.com> on 2011-01-14
#   - To get the vulnerable file version on windows vista
#
# Updated By: Sooraj KS <kssooraj@secpod.com> on 2011-07-18
#   - Updated Movie Maker path
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
  script_oid("1.3.6.1.4.1.25623.1.0.900232");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2010-03-10 15:48:25 +0100 (Wed, 10 Mar 2010)");
  script_bugtraq_id(38515);
  script_cve_id("CVE-2010-0265");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Windows Movie Maker Could Allow Remote Code Execution Vulnerability (975561)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/38791");
  script_xref(name:"URL", value:"http://support.microsoft.com/kb/975561");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code with the privileges of the user running the applications.");
  script_tag(name:"affected", value:"Movie Maker 2.1 on Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Producer 2003");
  script_tag(name:"insight", value:"The flaw is present since applications fails to perform adequate boundary
  checks on user-supplied data.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS10-016.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms10-016.mspx");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(registry_key_exists(key:"SOFTWARE\Microsoft\Producer"))
{
  uninstall = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  keys = registry_enum_keys(key:uninstall);
  foreach key (keys)
  {
    ## Report vulnerable, if it is Microsoft Producer 2003
    ## as there is no patch available
    producerName = registry_get_sz(key:uninstall + key, item:"DisplayName");
    if(producerName =~ "Microsoft Producer .* 2003")
    {
      security_message( port: 0, data: "The target host was found to be vulnerable" );
      exit(0);
    }

    if("Microsoft Producer for Microsoft Office PowerPoint" >< producerName)
    {
      producerVer = registry_get_sz(key:uninstall + key, item:"DisplayVersion");
      if(!isnull(producerVer))
      {
        if(version_is_less(version:producerVer, test_version:"3.0.3012.0"))
        {
          security_message( port: 0, data: "The target host was found to be vulnerable" );
          exit(0);
        }
      }
    }
  }
}

if(hotfix_check_sp(xp:4, winVista:3) <= 0){
  exit(0);
}

## MS10-016 Hotfix check
if(hotfix_missing(name:"975561") == 0){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                            "\App Paths\moviemk.exe")){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
if(!sysPath){
  exit(0);
}

## Movie Maker path
moviemkPath = sysPath + "\Movie Maker\moviemk.exe";

share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:moviemkPath);
file = ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:moviemkPath);

moviemkVer = GetVer(file:file, share:share);
if(!moviemkVer){
  exit(0);
}

if(hotfix_check_sp(xp:4) > 0)
{
  SP = get_kb_item("SMB/WinXP/ServicePack");
  if("Service Pack 2" >< SP || "Service Pack 3" >< SP)
  {
    if(version_in_range(version:moviemkVer, test_version:"2.1",
                                            test_version2:"2.1.4026.0")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
}

else if(hotfix_check_sp(winVista:3) > 0)
{
  SP = get_kb_item("SMB/WinVista/ServicePack");
  if("Service Pack 1" >< SP)
  {
    if(version_in_range(version:moviemkVer, test_version:"6.0", test_version2:"6.0.6001.18340")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }

  if("Service Pack 2" >< SP)
  {
    if(version_in_range(version:moviemkVer, test_version:"6.0", test_version2:"6.0.6002.18120")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
  }
  security_message( port: 0, data: "The target host was found to be vulnerable" );
}

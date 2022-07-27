###############################################################################
# OpenVAS Vulnerability Test
#
# Vulnerabilities in DNS and WINS Server Could Allow Spoofing (962238)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
#  Updated By: Madhuri D <dmadhuri@secpod.com> on 2010-12-03
#       - To detect file version 'dns.exe' on win 2008 server
#
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
  script_oid("1.3.6.1.4.1.25623.1.0.900088");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2009-03-11 16:41:30 +0100 (Wed, 11 Mar 2009)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:P");
  script_cve_id("CVE-2009-0233", "CVE-2009-0234", "CVE-2009-0093", "CVE-2009-0094");
  script_bugtraq_id(33982, 33988, 33989, 34013);
  script_name("Vulnerabilities in DNS and WINS Server Could Allow Spoofing (962238)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_xref(name:"URL", value:"https://docs.microsoft.com/en-us/security-updates/securitybulletins/2009/ms09-008");

  script_tag(name:"impact", value:"Successful exploitation could allow attacker to execute specially crafted
  DNS queries to poison the DNS cache and can redirect traffic by registering WPAD or ISATP in the WINS
  database pointing to any desired IP address.");

  script_tag(name:"affected", value:"Microsoft Windows 2K Server Service Pack 4 and prior.

  Microsoft Windows 2003 Server Service Pack 2 and prior.

  Microsoft Windows Server 2008 Service Pack 1 and prior.");

  script_tag(name:"insight", value:"- Error in the Windows DNS server may cause it to not properly reuse cached
    responses.

  - Error in the Windows DNS server may cause it to not properly cache
    responses to specifially crafted DNS queries.

  - Failure in access validation to restrict access when defining WPAD and
    ISATAP entries.");

  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");

  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS09-008.");

  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(win2k:5, win2003:3, win2008:2) <= 0){
  exit(0);
}

function get_ver(exeFile)
{
  exePath = registry_get_sz(item:"Install Path", key:"SOFTWARE\Microsoft\COM3\Setup");
  if(!exePath){
    return(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:exePath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:exePath + exeFile);
  fileVer = GetVer(file:file, share:share);
  if(fileVer){
    return fileVer;
  }
  else return(0);
}

if(registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\WINS"))
{
  if(hotfix_missing(name:"961064") == 1) #Grep for WINS Hotfix 961064 (MS09-008)
  {
    fileVer = get_ver(exeFile:"\wins.exe");
    if(fileVer)
    {
      if(get_kb_item("SMB/Win2K/ServicePack")) # Win-2000 SP4 and prior
      {
        if(version_is_less(version:fileVer, test_version:"5.0.2195.7241")){
          report = report_fixed_ver(installed_version:fileVer, fixed_version:"5.0.2195.7241");
          security_message(port:0, data:report);
        }
      }

      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP) # Win-2003 SP1
      {
        if(version_is_less(version:fileVer, test_version:"5.2.3790.3281")){
          report = report_fixed_ver(installed_version:fileVer, fixed_version:"5.2.3790.3281");
          security_message(port:0, data:report);
        }
      }
      else if("Service Pack 2" >< SP) # Win-2003 SP2
      {
        if(version_is_less(version:fileVer, test_version:"5.2.3790.4446")){
          report = report_fixed_ver(installed_version:fileVer, fixed_version:"5.2.3790.4446");
          security_message(port:0, data:report);
        }
      }
    }
  }
}

if(!registry_key_exists(key:"SYSTEM\CurrentControlSet\Services\DNS")){
  exit(0);
}

if(hotfix_missing(name:"961063") == 1) #Grep for DNS Hotfix 961063 (MS09-008)
{
  fileVer = get_ver(exeFile:"\dns.exe");
  if(fileVer)
  {
    if(get_kb_item("SMB/Win2K/ServicePack")) # Win-2000 SP4 and prior
    {
      if(version_is_less(version:fileVer, test_version:"5.0.2195.7260")){
        report = report_fixed_ver(installed_version:fileVer, fixed_version:"5.0.2195.7260");
        security_message(port:0, data:report);
      }
      exit(0);
    }

    SP = get_kb_item("SMB/Win2003/ServicePack");
    if("Service Pack 1" >< SP) # Win-2003 SP1
    {
      if(version_is_less(version:fileVer, test_version:"5.2.3790.3295")){
        report = report_fixed_ver(installed_version:fileVer, fixed_version:"5.2.3790.3295");
        security_message(port:0, data:report);
      }
      exit(0);
    }
    else if("Service Pack 2" >< SP) # Win-2003 SP2
    {
      if(version_is_less(version:fileVer, test_version:"5.2.3790.4460")){
        report = report_fixed_ver(installed_version:fileVer, fixed_version:"5.2.3790.4460");
        security_message(port:0, data:report);
      }
      exit(0);
    }
  }

  sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion", item:"PathName");
  if(!sysPath){
    exit(0);
  }

  share = ereg_replace(pattern:"([A-Z]):.*", replace:"\1$", string:sysPath);
  file =  ereg_replace(pattern:"[A-Z]:(.*)", replace:"\1", string:sysPath + "\System32\dns.exe");

  exeVer = GetVer(file:file, share:share);
  if(exeVer)
  {
    SP = get_kb_item("SMB/Win2008/ServicePack");
    if("Service Pack 1" >< SP)
    {
      if(version_is_less(version:exeVer, test_version:"6.0.6001.18214")){
        report = report_fixed_ver(installed_version:exeVer, fixed_version:"6.0.6001.18214");
        security_message(port:0, data:report);
      }
      exit(0);
    }
  }
}

exit( 99 );
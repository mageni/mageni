###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Internet Information Services Privilege Elevation Vulnerability (942831)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Updated by : Antu Sanadi <santu@secpod.com> on 2012-06-05
#  - Added IIS installation confirmation.
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.801704");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-13 17:08:42 +0100 (Thu, 13 Jan 2011)");
  script_cve_id("CVE-2008-0074");
  script_bugtraq_id(27101);
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Internet Information Services Privilege Elevation Vulnerability (942831)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/28849");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2008/Feb/1019384.html");
  script_xref(name:"URL", value:"http://technet.microsoft.com/en-us/security/bulletin/ms08-005");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl", "gb_ms_iis_detect_win.nasl");
  script_mandatory_keys("MS/IIS/Ver", "SMB/registry_enumerated");
  script_require_ports(139, 445);
  script_tag(name:"impact", value:"Successful exploitation could allow remote attackers to execute arbitrary
  code with SYSTEM-level privileges.");
  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 3 and prior.
  Microsoft Windows 2K Service Pack 4 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista
  Microsoft Internet Information Services (IIS) version 5.0
  Microsoft Internet Information Services (IIS) version 5.1
  Microsoft Internet Information Services (IIS) version 6.0
  Microsoft Internet Information Services (IIS) version 7.0");
  script_tag(name:"insight", value:"The flaw is due to an error within the handling of file change
  notifications in the 'FTPRoot', 'NNTPFile\Root', and 'WWWRoot' folders.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS08-005.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:4, win2003:3, winVista:3, win2k:5) <= 0){
  exit(0);
}

iisVer = get_kb_item("MS/IIS/Ver");
if(!iisVer){
  exit(0);
}

if(hotfix_missing(name:"942831") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"inetsrv\infocomm.dll");
  if(sysVer)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(version_is_less(version:sysVer, test_version:"5.0.2195.7147")){
        security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      exit(0);
    }

    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
         if(version_is_less(version:sysVer, test_version:"6.0.2600.3290")){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"6.0.3790.4215")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }

      if ("Service Pack 1" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"6.0.3790.3068")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
  }
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows NT\CurrentVersion",
                      item:"PathName");
if(!sysPath){
  exit(0);
}

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\inetsrv\infocomm.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
    if(version_is_less(version:sysVer, test_version:"7.0.6000.16576")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }
    exit(0);
}

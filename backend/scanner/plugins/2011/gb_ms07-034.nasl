###############################################################################
# OpenVAS Vulnerability Test
#
# Microsoft Outlook Express/Windows Mail MHTML URI Handler Information Disclosure Vulnerability (929123)
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.801716");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2011-01-14 09:03:25 +0100 (Fri, 14 Jan 2011)");
  script_cve_id("CVE-2006-2111", "CVE-2007-1658", "CVE-2007-2225", "CVE-2007-2225");
  script_bugtraq_id(17717);
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_name("Microsoft Outlook Express/Windows Mail MHTML URI Handler Information Disclosure Vulnerability (929123)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/22477");
  script_xref(name:"URL", value:"http://xforce.iss.net/xforce/xfdb/26281");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2006/Apr/1016005.html");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms07-034.mspx");

  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allows remote attackers to gain access to sensitive
  information that is associated with the external domain.");
  script_tag(name:"affected", value:"Microsoft Windows XP Service Pack 2 and prior.
  Microsoft Windows 2K3 Service Pack 2 and prior.
  Microsoft Windows Vista");
  script_tag(name:"insight", value:"The flaw is due to

  - Error in Windows because the 'MHTML' protocol handler incorrectly interprets
    the MHTML URL redirections that could potentially bypass Internet Explorer
    domain restrictions.

  - The way local or UNC navigation requests are handled in Windows Mail.

  - Error in Windows because the 'MHTML' protocol handler incorrectly interprets
    HTTP headers when returning MHTML content.

  - MHTML protocol handler, which passes Content-Disposition notifications back to
    Internet Explorer.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"This host is missing a critical security update according to
  Microsoft Bulletin MS07-034.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(hotfix_check_sp(xp:3, win2003:3, winVista:3) <= 0){
  exit(0);
}

if(hotfix_missing(name:"929123") == 0){
  exit(0);
}

sysPath = registry_get_sz(key:"SOFTWARE\Microsoft\COM3\Setup",
                          item:"Install Path");
if(sysPath)
{
  sysVer = fetch_file_version(sysPath:sysPath, file_name:"Inetcomm.dll");
  if(sysVer)
  {
    if(hotfix_check_sp(xp:3) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if("Service Pack 2" >< SP)
      {
         if(version_is_less(version:sysVer, test_version:"6.0.2900.3138")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }
      security_message( port: 0, data: "The target host was found to be vulnerable" );
    }

    else if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"6.0.3790.2929")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }
      if("Service Pack 2" >< SP)
      {
        if(version_is_less(version:sysVer, test_version:"6.0.3790.4073")){
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

sysVer = fetch_file_version(sysPath:sysPath, file_name:"system32\Inetcomm.dll");
if(!sysVer){
  exit(0);
}

if(hotfix_check_sp(winVista:3) > 0)
{
  if(version_is_less(version:sysVer, test_version:"6.0.6000.16480")){
      security_message( port: 0, data: "The target host was found to be vulnerable" );
  }
  exit(0);
}

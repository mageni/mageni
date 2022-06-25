###############################################################################
# OpenVAS Vulnerability Test
#
# Cumulative Security Update for Internet Explorer (950759)
#
# Authors:
# Veerendra GG <veerendragg@secpod.com>
#
#  Updated by Madhuri D <dmadhuri@secpod.com> on 2010-12-09
#    - To detect the 'mshtml.dll' file version on Windows vista and 2008 server
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
  script_oid("1.3.6.1.4.1.25623.1.0.800103");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-09-29 16:48:05 +0200 (Mon, 29 Sep 2008)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2008-1442", "CVE-2008-1544");
  script_bugtraq_id(28379, 29556);
  script_name("Cumulative Security Update for Internet Explorer (950759)");
  script_xref(name:"URL", value:"http://secunia.com/advisories/30575");
  script_xref(name:"URL", value:"http://secunia.com/advisories/29453");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/0980");
  script_xref(name:"URL", value:"http://www.frsirt.com/english/advisories/2008/1778");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-031.mspx");

  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2008 Intevation GmbH");
  script_family("Windows : Microsoft Bulletins");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation allow remote attackers to execute arbitrary
  code by tricking user into visiting a specially crafted web page and to read
  data from a Web page in another domain in Internet Explorer. Attackers can
  use above issues to poison web caches, steal credentials, launch cross-site
  scripting, HTML-injection, and session-hijacking attacks.");
  script_tag(name:"affected", value:"Microsoft Internet Explorer 5.01 & 6 SP1 for Microsoft Windows 2000
  Microsoft Internet Explorer 6 for Microsoft Windows 2003 and XP
  Microsoft Internet Explorer 7 for Microsoft Windows 2003 and XP
  Microsoft Internet Explorer 7 on MS Windows 2008 and Vista");
  script_tag(name:"insight", value:"The flaws are due to

  - a memory corruption error while processing a Web page that contains certain
    unexpected method calls to HTML objects.

  - failure of setRequestHeader method of the XMLHttpRequest object to block
    dangerous HTTP request headers when certain 8-bit character sequences are
    appended to a header name.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"summary", value:"This host has Microsoft Internet Explorer installed, which is
  prone to HTTP request splitting/smuggling and HTML Objects Memory Corruption
  Vulnerabilities.");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("secpod_ie_supersede.inc");

if(hotfix_check_sp(win2k:5, xp:4, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

sysFile = smb_get_system32root();
if(!sysFile){
  exit(0);
}

sysFile += "\mshtml.dll";

ieVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer",
                        item:"Version");
if(!ieVer){
  ieVer = registry_get_sz(item:"IE",
                   key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
}

if(!ieVer){
  exit(0);
}

# Supersede check for MS08-045 and later
if(ie_latest_hotfix_update(bulletin:"MS08-031")){
  exit(0);
}

# MS08-031 Hotfix check
if(hotfix_missing(name:"950759") == 0){
  exit(0);
}

if(hotfix_check_sp(win2k:5) > 0)
{
  vers = get_version(dllPath:sysFile, string:"prod", offs:2000000);
  if(vers == NULL){
    exit(0);
  }

  if(ereg(pattern:"^5\..*", string:ieVer))
  {
    if(ereg(pattern:"(5\.00\.(([0-2]?[0-9]?[0-9]?[0-9]|3?([0-7][0-9][0-9]" +
                    "|8([0-5][0-9]|6[0-3])))(\..*)|3864\.(0?[0-9]?[0-9]?"  +
                    "[0-9]|1[0-7][0-9][0-9])))$", string:vers)){
      security_message(get_kb_item("SMB/transport"));
    }
    exit(0);
  }

  if(ereg(pattern:"^6\..*", string:ieVer))
  {
    if(ereg(pattern:"(6\.00\.(([01]?[0-9]?[0-9]?[0-9]|2([0-7][0-9][0-9]" +
                    "))(\..*)|2800\.(0?[0-9]?[0-9]?[0-9]|1([0-5][0-9]" +
                    "[0-9]|6(0[0-9]|10)))))$", string:vers)){
      security_message(get_kb_item("SMB/transport"));
    }
    exit(0);
  }
}

if(hotfix_check_sp(xp:4) > 0)
{
  vers = get_version(dllPath:sysFile, string:"prod", offs:2000000);
  if(vers == NULL){
    exit(0);
  }

  SP = get_kb_item("SMB/WinXP/ServicePack");
  if(ereg(pattern:"^6\..*", string:ieVer))
  {
    if("Service Pack 2" >< SP)
    {
      if(ereg(pattern:"(6\.00\.(([01]?[0-9]?[0-9]?[0-9]|2([0-8][0-9]" +
                      "[0-9]))(\..*)|2900\.([0-2]?[0-9]?[0-9]?[0-9]|3(" +
                      "[0-2][0-9][0-9]|3([0-4][0-9]|5[0-3])))))$",
              string:vers)){
        security_message(get_kb_item("SMB/transport"));
      }
      exit(0);
    }
    if("Service Pack 3" >< SP)
    {
      if(ereg(pattern:"(6\.00\.(([01]?[0-9?[0-9]?[0-9]|2[0-8][0-9][0-9]" +
                      ")(\..*)|2900\.([0-4]?[0-9]?[0-9]?[0-9]|5([0-4]" +
                      "[0-9][0-9]|5([0-7][0-9]|8[0-2])))))$",
              string:vers)){
        security_message(get_kb_item("SMB/transport"));
      }
      exit(0);
    }
  }

  if(ereg(pattern:"^7\..*", string:ieVer))
  {
    if(ereg(pattern:"(7\.00\.([0-5]?[0-9]?[0-9]?[0-9]\..*|6000\.(0?[0-9]?" +
                    "[0-9]?[0-9]?[0-9]|1([0-5][0-9][0-9][0-9]|6([0-5]" +
                    "[0-9][0-9]|6([0-6][0-9]|7[0-3]))))))$",
            string:vers)){
      security_message(get_kb_item("SMB/transport"));
    }
    exit(0);
  }
}

if(hotfix_check_sp(win2003:3) > 0)
{
  vers = get_version(dllPath:sysFile, string:"prod", offs:2000000);
  if(vers == NULL){
    exit(0);
  }

  SP = get_kb_item("SMB/Win2003/ServicePack");
  if(ereg(pattern:"^6\..*", string:ieVer))
  {
    if("Service Pack 2" >< SP)
    {
      if(ereg(pattern:"(6\.00\.(([0-2]?[0-9]?[0-9][0-9]|3([0-6][0-9][0-9]" +
                      "|7[0-8][0-9]))(\..*)|3790\.([0-3]?[0-9]?[0-9]?[0-9]" +
                      "|4([01][0-9][0-9]|2([0-6][0-9]|7[0-4])))))$",
              string:vers)){
        security_message(get_kb_item("SMB/transport"));
      }
      exit(0);
    }
    if("Service Pack 1" >< SP)
    {
      if(ereg(pattern:"(6\.00\.(([0-2]?[0-9]?[0-9]?[0-9]|3([0-6][0-9]" +
                       "[0-9]|7[0-8][0-9]))(\..*)|3790\.([0-2]?[0-9]?" +
                       "[0-9]?[0-9]|3(0[0-9][0-9]|1([01][0-9]|2[0-2]" +
                       ")))))$", string:vers)){
         security_message(get_kb_item("SMB/transport"));
      }
      exit(0);
    }
  }

  if(ereg(pattern:"^7\..*", string:ieVer))
  {
    if(ereg(pattern:"(7\.00\.([0-5]?[0-9]?[0-9]?[0-9]\..*|6000\.(0?[0-9]?" +
                    "[0-9]?[0-9]?[0-9]|1([0-5][0-9][0-9][0-9]|6([0-5]" +
                    "[0-9][0-9]|6([0-6][0-9]|7[0-3]))))))$",
            string:vers)){
      security_message(get_kb_item("SMB/transport"));
    }
    exit(0);
  }
}

 dllPath = smb_get_system32root();
 if(!dllPath){
   exit(0);
 }

 dllVer = fetch_file_version(sysPath:dllPath, file_name:"\mshtml.dll");
 if(dllVer)
 {
   if(hotfix_check_sp(winVista:2) > 0)
   {
     SP = get_kb_item("SMB/WinVista/ServicePack");
     if("Service Pack 1" >< SP)
     {
       if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18062")){
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
       if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18062")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
       }
         exit(0);
     }
   }
 }

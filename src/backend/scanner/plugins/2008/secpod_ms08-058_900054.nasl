##############################################################################
# OpenVAS Vulnerability Test
# Description: Cumulative Security Update for Internet Explorer (956390)
#
# Authors:
# Chandan S <schandan@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
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
##############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900054");
  script_version("2019-05-03T10:54:50+0000");
  script_tag(name:"last_modification", value:"2019-05-03 10:54:50 +0000 (Fri, 03 May 2019)");
  script_tag(name:"creation_date", value:"2008-10-15 19:56:48 +0200 (Wed, 15 Oct 2008)");
  script_bugtraq_id(29960, 31615, 31616, 31617, 31618, 31654);
  script_cve_id("CVE-2008-2947", "CVE-2008-3472", "CVE-2008-3473",
                "CVE-2008-3474", "CVE-2008-3475", "CVE-2008-3476");
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Windows : Microsoft Bulletins");
  script_name("Cumulative Security Update for Internet Explorer (956390)");
  script_xref(name:"URL", value:"http://www.microsoft.com/technet/security/bulletin/ms08-058.mspx");
  script_dependencies("secpod_reg_enum.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/registry_enumerated");

  script_tag(name:"impact", value:"Successful exploitation could allow attackers to execute arbitrary
  code via a malicious web page and can gain access to a browser window in
  another domain leading read cookies or cross domain scripting attacks.");
  script_tag(name:"affected", value:"Internet Explorer 5.01 & 6 on MS Windows 2000
  Internet Explorer 6 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows 2003 and XP
  Internet Explorer 7 on MS Windows 2008 and Vista");
  script_tag(name:"insight", value:"Multiple flaws are due to,

  - the browser incorrectly interpreting the origin of scripts when setting the
    Window location object.

  - the browser incorrectly interpreting the origin of scripts when handling
    certain HTML elements.

  - the browser incorrectly interpreting the origin of scripts when handling
    certain events.

  - a memory corruption error when the browser attempts to access an object
    which has not been initialized or has been deleted.

  - a memory corruption error when the browser attempts to access uninitialized
    memory while processing certain HTML objects.");
  script_tag(name:"summary", value:"This host is missing critical security update according to
  Microsoft Bulletin MS08-058.");
  script_tag(name:"solution", value:"The vendor has released updates. Please see the references for more information.");
  script_tag(name:"qod_type", value:"registry");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("smb_nt.inc");
include("secpod_reg.inc");
include("version_func.inc");
include("secpod_smb_func.inc");
include("secpod_ie_supersede.inc");



if(hotfix_check_sp(xp:4, win2k:5, win2003:3, win2008:2, winVista:2) <= 0){
  exit(0);
}

ieVer = registry_get_sz(key:"SOFTWARE\Microsoft\Internet Explorer",
                        item:"Version");
if(!ieVer){
  ieVer = registry_get_sz(item:"IE",
          key:"SOFTWARE\Microsoft\Internet Explorer\Version Vector");
}

if(!ieVer){
  exit(0);
}

if(ie_latest_hotfix_update(bulletin:"MS08-058")){
  exit(0);
}

if(hotfix_missing(name:"956390") == 0){
  exit(0);
}

sysPath = smb_get_system32root();
if(sysPath)
{
  vers = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(vers)
  {
    if(hotfix_check_sp(win2k:5) > 0)
    {
      if(ereg(pattern:"^5\..*", string:ieVer))
      {
        if(ereg(pattern:"^(5\.0?0\.(([0-2]?[0-9]?[0-9]?[0-9]|3?([0-7]?"+
                    "[0-9]?[0-9]|8?([0-5]?[0-9]|6[0-7])))(\..*)|"+
                    "3868\.[01]?[0-9]?[0-9]?[0-9]))$", string:vers)){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }

      if(ereg(pattern:"^6\..*", string:ieVer))
      {
        if(ereg(pattern:"^(6\.0?0\.(([01]?[0-9]?[0-9]?[0-9]|2?([0-7]?["+
                    "0-9]?[0-9]))(\..*)|2800\.(0?[0-9]?[0-9]?[0-"+
                    "9]|1([0-5][0-9][0-9]|6(0[0-9]|1[0-4])))))$",
            string:vers)){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }

    if(hotfix_check_sp(xp:4) > 0)
    {
      SP = get_kb_item("SMB/WinXP/ServicePack");
      if(ereg(pattern:"^6\..*", string:ieVer))
      {
        if("Service Pack 2" >< SP)
        {
          if(ereg(pattern:"^(6\.0?0\.(([01]?[0-9]?[0-9]?[0-9]|2?([0-8]?["+
                      "0-9]?[0-9]))(\..*)|2900\.([0-2]?[0-9]?[0-9]"+
                      "?[0-9]|3([0-3][0-9][0-9]|4([01][0-9]"+
                      "|2[0-8])))))$", string:vers)){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }
        if("Service Pack 3" >< SP)
        {
          if(ereg(pattern:"^(6\.0?0\.(([01]?[0-9]?[0-9]?[0-9]|2?([0-8]?["+
                      "0-9]?[0-9]))(\..*)|2900\.([0-4]?[0-9]?[0-9]"+
                      "?[0-9]|5([0-5][0-9][0-9]|6([0-4][0-9]"+
                      "|5[0-8])))))$", string:vers)){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }
        else security_message( port: 0, data: "The target host was found to be vulnerable" );
      }

      if(ereg(pattern:"^7\..*", string:ieVer))
      {
        if(ereg(pattern:"^(7\.0?0\.([0-5]?[0-9]?[0-9]?[0-9]\..*|6000\."+
                    "(0?[0-9]?[0-9]?[0-9]?[0-9]|1([0-5][0-9]"+
                    "[0-9][0-9]|6([0-6][0-9][0-9]|7[0-2][0-9]|73[0-4])))))$",
            string:vers)){
           security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }

    if(hotfix_check_sp(win2003:3) > 0)
    {
      SP = get_kb_item("SMB/Win2003/ServicePack");
      if(ereg(pattern:"^6\..*", string:ieVer))
      {
        if("Service Pack 1" >< SP)
        {
          if(ereg(pattern:"(6\.0?0\.(([0-2]?[0-9]?[0-9]?[0-9]|3([0-6]"+
                      "[0-9][0-9]|7[0-8][0-9]))(\..*)|3790\.([0"+
                      "-2]?[0-9]?[0-9]?[0-9]|3(0[0-9][0-9]|1(["+
                      "0-8][0-9]|9[0-3])))))$", string:vers)){
            security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }

        if("Service Pack 2" >< SP)
        {
          if(ereg(pattern:"(6\.0?0\.(([0-2]?[0-9]?[0-9]?[0-9]|3([0-6]"+
                      "[0-9][0-9]|7[0-8][0-9]))(\..*)|3790\.([0"+
                      "-3]?[0-9]?[0-9]?[0-9]|4([0-2][0-9][0-9]|3(["+
                      "0-4][0-9]|5[0-6])))))$", string:vers)){
             security_message( port: 0, data: "The target host was found to be vulnerable" );
          }
          exit(0);
        }
        else security_message( port: 0, data: "The target host was found to be vulnerable" );
      }
      if(ereg(pattern:"^7\..*", string:ieVer))
      {
        if(ereg(pattern:"(7\.0?0\.([0-5]?[0-9]?[0-9]?[0-9]\..*|6000\."+
                    "(0?[0-9]?[0-9]?[0-9]?[0-9]|1([0-5][0-9]"+
                    "[0-9][0-9]|6([0-6][0-9][0-9]|7[0-2][0-9]|73[0-4])))))$",
            string:vers)){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
        exit(0);
      }
    }
  }
}

sysPath = smb_get_system32root();
if(sysPath)
{
  dllVer = fetch_file_version(sysPath:sysPath, file_name:"mshtml.dll");
  if(dllVer)
  {
    if(hotfix_check_sp(winVista:2) > 0)
    {
      SP = get_kb_item("SMB/WinVista/ServicePack");
      if("Service Pack 1" >< SP)
      {
        if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18147")){
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
        if(version_in_range(version:dllVer, test_version:"7.0", test_version2:"7.0.6001.18147")){
          security_message( port: 0, data: "The target host was found to be vulnerable" );
        }
         exit(0);
      }
    }
  }
}

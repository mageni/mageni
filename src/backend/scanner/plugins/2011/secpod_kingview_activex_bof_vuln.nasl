###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_kingview_activex_bof_vuln.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# WellinTech KingView 'KVWebSvr.dll' ActiveX Control Heap Buffer Overflow Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.902724");
  script_version("$Revision: 11997 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)");
  script_cve_id("CVE-2011-3142");
  script_bugtraq_id(46757);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("WellinTech KingView 'KVWebSvr.dll' ActiveX Control Heap Buffer Overflow Vulnerability");


  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Buffer overflow");
  script_dependencies("smb_reg_service_pack.nasl");
  script_require_ports(139, 445);
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name:"insight", value:"The flaw exists due to error in 'KVWebSvr.dll' file, when 'ValidateUser'
  method in an ActiveX component called with an specially crafted argument to
  cause a stack-based buffer overflow.");
  script_tag(name:"summary", value:"This host is installed with KingView and is prone to buffer
  overflow vulnerability.");
  script_tag(name:"solution", value:"Upgrade KVWebSrv.dll file version to 65.30.2010.18019  *****
  NOTE : Ignore this warning, if above mentioned patch is applied already.
  *****");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary
  code in the context of the application. Failed attacks will cause
  denial-of-service conditions.");
  script_tag(name:"affected", value:"KingView version 6.53 and 6.52");
  script_xref(name:"URL", value:"http://www.cnvd.org.cn/vulnerability/CNVD-2011-04541");
  script_xref(name:"URL", value:"http://www.kingview.com/news/detail.aspx?contentid=537");
  script_xref(name:"URL", value:"http://www.us-cert.gov/control_systems/pdf/ICSA-11-074-01.pdf");
  script_xref(name:"URL", value:"http://download.kingview.com/software/kingview%20Chinese%20Version/KVWebSvr.rar");
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\WellinControl Technology Development Co.,Ltd.")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";

if(!registry_key_exists(key:key)){
  exit(0);
}

foreach item(registry_enum_keys(key:key))
{
  kvName = registry_get_sz(key:key + item, item:"DisplayName");

  if("Kingview" >< kvName)
  {
    kvVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(kvVer!= NULL)
    {
      if(version_is_equal(version:kvVer, test_version:"6.52") ||
         version_is_equal(version:kvVer, test_version:"6.53"))
      {
        dllPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion",
                          item:"ProgramFilesDir");
        if(dllPath)
        {
          dllVer = fetch_file_version(sysPath:dllPath, file_name:"Kingview\KVWebSvr.dll");
          {
            if(version_is_less(version:dllVer, test_version:"65.30.2010.18019")){
               security_message( port: 0, data: "The target host was found to be vulnerable" );
            }
          }
        }
      }
    }
  }
}

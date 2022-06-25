###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_foxit_phantom_reader_detect.nasl 2015-04-08 10:37:27 +0530 Apr$
#
# Foxit PhantomPDF Version Detection
#
# Authors:
# Deependra Bapna <bdeependra@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.805362");
  script_version("$Revision: 11356 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-12 12:46:43 +0200 (Wed, 12 Sep 2018) $");
  script_tag(name:"creation_date", value:"2015-04-08 10:37:27 +0530 (Wed, 08 Apr 2015)");
  script_name("Foxit PhantomPDF Version Detection");

  script_tag(name:"summary", value:"Detects the installed version of
  Foxit PhantomPDF.

  The script logs in via smb, searches for Foxit Reader in the registry and
  gets the version from registry.");
  script_tag(name:"qod_type", value:"executable_version");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Foxit Software\Foxit PhantomPDF");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Wow6432Node\Foxit Software\Foxit PhantomPDF");
}

if(isnull(key_list)){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\Foxit Software\Foxit PhantomPDF")){
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Foxit Software\Foxit PhantomPDF")){
    exit(0);
  }
}

foreach key (key_list)
{
  foxitVer = registry_get_sz(key:key, item:"Version");
  foxitPath = registry_get_sz(key:key, item:"InstallPath");
  if(!foxitPath){
    foxitPath = registry_get_sz(key:key, item:"InstallLocation");
  }

  if(!foxitVer)
  {
    if(foxitPath){
      foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit PhantomPDF.exe");
       if(!foxitVer){
         foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitPhantomPDF.exe");
       }
     }
    else
    {
      foxitPath = registry_get_sz(key:key, item:"InnoSetupUpdatePath");
      if(foxitPath)
      {
        foxitPath = foxitPath - "unins000.exe";
        foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"Foxit PhantomPDF.exe");
        if(!foxitVer){
         foxitVer = fetch_file_version(sysPath:foxitPath, file_name:"FoxitPhantomPDF.exe");
       }

      }
    }
  }

  if(foxitVer)
  {
    set_kb_item(name:"foxit/phantompdf/ver", value:foxitVer);

    if(!foxitPath){
      foxitPath = 'Could not find the install path from registry';
    }
    cpe = build_cpe(value:foxitVer, exp:"^([0-9.]+)", base:"cpe:/a:foxitsoftware:phantompdf:");
    if(isnull(cpe))
      cpe = "cpe:/a:foxitsoftware:phantompdf";

    register_product(cpe:cpe, location:foxitPath);

    log_message(data: build_detection_report(app:"Foxit PhantomPDF",
                                             version:foxitVer,
                                             install:foxitPath,
                                             cpe:cpe,
                                             concluded:foxitVer));
  }
}

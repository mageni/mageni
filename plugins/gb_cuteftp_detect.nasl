##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cuteftp_detect.nasl 10911 2018-08-10 15:16:34Z cfischer $
#
# CuteFTP Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-07
# Updated according to CR57 and to support 32 and 64 bit.
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
  script_oid("1.3.6.1.4.1.25623.1.0.800947");
  script_version("$Revision: 10911 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:16:34 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-10-20 14:26:56 +0200 (Tue, 20 Oct 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("CuteFTP Version Detection (Windows)");


  script_tag(name:"summary", value:"Detects the installed version of CuteFTP on Windows.

The script logs in via smb, searches for CuteFTP in the registry
and gets the install location and extract version from the file.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
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

appKey_list = make_list("SOFTWARE\GlobalSCAPE", "SOFTWARE\GlobalSCAPE Inc.",
                        "SOFTWARE\Wow6432Node\GlobalSCAPE", "SOFTWARE\Wow6432Node\GlobalSCAPE Inc.");
foreach appKey (appKey_list)
{
  if(registry_key_exists(key:appKey))
  {
    appExists = TRUE;
    break;
  }
}

if (!appExists) exit(0);

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

## Presently CuteFTP 64bit application is not available
else if("x64" >< os_arch){
  key_list =  make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    cName = registry_get_sz(key:key + item, item:"DisplayName");

    if("CuteFTP" >< cName)
    {
      ## To check whether it is Home/Lite/Professional
      cftpName = eregmatch(pattern:"CuteFTP [0-9.?]+ ([a-zA-Z]+)",string:cName);

      cPath = registry_get_sz(key:key + item, item:"DisplayIcon");
      if(cPath == NULL){
        exit(0);
      }

      cPath = cPath - ",-0";
      cpath_list = split(cPath, sep:"\", keep:0);

      exeName = cpath_list[max_index(cpath_list)-1];

      cftpVer = fetch_file_version(sysPath: cPath - exeName, file_name: exeName);

      if(cftpVer)
      {
        ## Will work only on older versions from 1 to 8
        ## and set KB as CuteFTP/Home/Ver (or) CuteFTP/Lite/Ver (or) CuteFTP/Professional/Ver
        if (cftpName[1]) {
            set_kb_item(name:"CuteFTP/"+string(cftpName[1])+"/Ver", value:cftpVer);
        }

        ## Used for Common application Detection
        set_kb_item(name:"CuteFTP/Win/Ver", value:cftpVer);

        cpe = build_cpe(value:cftpVer, exp:"^([0-9.]+([a-z0-9]+)?)", base:"cpe:/a:globalscape:cuteftp:");
        if(isnull(cpe))
          cpe = "cpe:/a:globalscape:cuteftp";

        register_product(cpe:cpe, location:cPath);

        log_message(data: build_detection_report(app: cName,
                                                 version: cftpVer,
                                                 install: cPath,
                                                 cpe: cpe,
                                                 concluded: cftpVer));
      }
    }
  }
}

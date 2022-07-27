###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_labtam_proftp_detect.nasl 11279 2018-09-07 09:08:31Z cfischer $
#
# Labtam ProFTP Version Detection
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-06-03
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900979");
  script_version("$Revision: 11279 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-07 11:08:31 +0200 (Fri, 07 Sep 2018) $");
  script_tag(name:"creation_date", value:"2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Labtam ProFTP Version Detection");

  script_tag(name:"summary", value:"This script detects the installed version of Labtam ProFTP and
sets the result in KB.

The script logs in via smb, searches for ProFTP in the registry
and gets the version from registry.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
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

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Lab-NC\ProFTP",
                       "SOFTWARE\Labtam\ProFtp");
  key_list2 = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\ProFTP");

}
else if("x64" >< os_arch)
{
  ##For some versions the path is not coming like below.
  key_list =  make_list("SOFTWARE\Wow6432Node\Lab-NC\ProFTP",
                        "SOFTWARE\Wow6432Node\Labtam\ProFtp");
  key_list2 = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\ProFTP");
}

if(!registry_key_exists(key:"SOFTWARE\Lab-NC\ProFTP")){
  if(!registry_key_exists(key:"SOFTWARE\Labtam\ProFtp")){
    if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Lab-NC\ProFTP")){
      if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Labtam\ProFtp")){
        exit(0);
      }
    }
  }
}

if(isnull(key_list && key_list2)){
  exit(0);
}

foreach key (key_list)
{
  foreach item(registry_enum_keys(key:key))
  {
    if(item =~ "[0-9]\.[0-9]")
    {
      ftpVer = item;

      foreach key1 (key_list2)
      {
        ftpPath = registry_get_sz(key:key1, item:"Path");
        if(!ftpPath){
          ftpPath = "Couldn find the install location from registry";
        }
      }

      if(ftpVer)
      {
        set_kb_item(name:"Labtam/ProFTP/Ver", value:ftpVer);

        cpe = build_cpe(value:item, exp:"^([0-9.]+)", base:"cpe:/a:labtam-inc:proftp:");
        if(isnull(cpe))
          cpe = "cpe:/a:labtam-inc:proftp:";

        register_product(cpe:cpe, location:ftpPath);
        log_message(data: build_detection_report(app: "Labtam ProFTP",
                                                 version:ftpVer,
                                                 install: ftpPath ,
                                                 cpe: cpe,
                                                 concluded:ftpVer));
      }
    }
  }
}

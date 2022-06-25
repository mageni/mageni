##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_winrar_detect.nasl 12974 2019-01-08 13:06:45Z cfischer $
#
# WinRAR Version Detection
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Updated By: Shakeel <bshakeel@secpod.com> on 2014-05-21
# According to CR57 and to support 32 and 64 bit.
#
# Copyright:
# Copyright (C) 2009 SecPod, http//www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.901021");
  script_version("$Revision: 12974 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2019-01-08 14:06:45 +0100 (Tue, 08 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-09-16 15:34:19 +0200 (Wed, 16 Sep 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("WinRAR Version Detection");

  script_tag(name:"summary", value:"This script finds the installed WinRAR and saves the version in KB.

  The script logs in via smb, searches for WinRAR in the registry and gets the version.");

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
include("version_func.inc");

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\WinRAR.exe");
}

if(isnull(key_list)){
  exit(0);
}

# nb: To make openvas-nasl-lint happy...
checkduplicate = "";
checkduplicate_path = "";

foreach key(key_list)
{
  rarPath =  registry_get_sz(key:key, item:"Path");
  if("WinRAR" >< rarPath)
  {
    rarVer = fetch_file_version(sysPath:rarPath , file_name: "WinRAR.exe");

    if(isnull(rarVer))
    {
      path = rarPath + "\WhatsNew.txt";
      rarVer = smb_read_file(fullpath:path, offset:0, count:1000);

      if(rarVer)
      {
        rarVer = eregmatch(pattern:"[v|V]ersion ([0-9.]+)", string:rarVer);
        if(rarVer[1]){
          rarVer = rarVer[1];
        }
      }
    }

    if (rarVer + ", " >< checkduplicate &&  rarPath + ", " >< checkduplicate_path){
      continue;
    }
    ##Assign detected version value to checkduplicate so as to check in next loop iteration
    checkduplicate  += rarVer + ", ";
    checkduplicate_path += rarPath + ", ";

    set_kb_item(name:"WinRAR/Ver", value:rarVer);

    cpe = build_cpe(value:rarVer, exp:"^([0-9.]+)", base:"cpe:/a:rarlab:winrar:");
    if(isnull(cpe))
      cpe = "cpe:/a:rarlab:winrar";

    if("64" >< os_arch && "Wow6432Node" >!< key && "x86" >!< rarPath)
    {
      set_kb_item(name:"WinRAR64/Ver", value:rarVer);

      cpe = build_cpe(value:rarVer, exp:"^([0-9.]+)", base:"cpe:/a:rarlab:winrar:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:rarlab:winrar:x64";
    }
    register_product(cpe:cpe, location:rarPath);

    log_message(data: build_detection_report(app: "WinRar",
                                             version: rarVer,
                                             install: rarPath,
                                             cpe: cpe,
                                             concluded: rarVer));

  }
}

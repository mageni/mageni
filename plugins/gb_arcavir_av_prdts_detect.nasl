##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_arcavir_av_prdts_detect.nasl 10908 2018-08-10 15:00:08Z cfischer $
#
# ArcaVir AntiVirus Products Version Detection
#
# Authors:
# Sujit Ghosal <sghosal@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http//www.greenbone.net
#
# Updated By: Thanga Prakash S <tprakash@secpod.com> on 2014-05-20
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
  script_oid("1.3.6.1.4.1.25623.1.0.800719");
  script_version("$Revision: 10908 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 17:00:08 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-06-04 07:18:37 +0200 (Thu, 04 Jun 2009)");
  script_tag(name:"qod_type", value:"registry");
  script_name("ArcaVir AntiVirus Products Version Detection");


  script_tag(name:"summary", value:"Detects the installed version of ArcaVir AntiVirus Products on Windows.

The script logs in via smb, searches for ArcaVir in the registry
and gets the install version from the registry.");

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

key = "SOFTWARE\ArcaBit";
if(!registry_key_exists(key:key))
{
  key = "SOFTWARE\Wow6432Node\ArcaBit";
  if(!registry_key_exists(key:key)){
    exit(0);
  }
}

os_arch = get_kb_item("SMB/Windows/Arch");
if(!os_arch){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

else if("x64" >< os_arch)
{
  key_list =  make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key (key_list)
{
  foreach item (registry_enum_keys(key:key))
  {
    arcaName = registry_get_sz(key:key + item, item:"DisplayName");

    if("ArcaVir" >< arcaName || "Arcabit" >< arcaName)
    {
      arcaPath = registry_get_sz(key:key + item, item:"DisplayIcon");
      if(arcaPath && "arcabit.exe" >< arcaPath){
        arcaPath = arcaPath - "arcabit.exe";
      }

      arcaVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(!arcaVer && arcaPath){
        arcaVer = fetch_file_version(sysPath:arcaPath, file_name:"arcabit.exe");
      }
      if(arcaVer != NULL)
      {
        if(!arcaPath){
          arcaPath = "Could not find the install Location from registry";
        }
        set_kb_item(name:"ArcaVir/AntiVirus/Ver", value:arcaVer);

        ## 2009 version is not available for download
        ## Latest version is 2014, so haven't changed the cpe setting.
        cpe = build_cpe(value:arcaVer, exp:"^(9\..*)", base:"cpe:/a:arcabit:arcavir_2009_antivirus_protection:");
        if(isnull(cpe))
          cpe = "cpe:/a:arcabit:arcavir_2009_antivirus_protection";

        if("64" >< os_arch && "Wow6432Node" >!< key)
        {
          set_kb_item(name:"ArcaVir64/AntiVirus/Ver", value:arcaVer);

          cpe = build_cpe(value:arcaVer, exp:"^(9\..*)", base:"cpe:/a:arcabit:arcavir_2009_antivirus_protection:x64:");
          if(isnull(cpe))
            cpe = "cpe:/a:arcabit:arcavir_2009_antivirus_protection:x64";
        }
        register_product(cpe:cpe, location:arcaPath);

        log_message(data: build_detection_report(app: arcaName,
                                           version: arcaVer,
                                           install: arcaPath,
                                           cpe: cpe,
                                           concluded: arcaVer));

      }
    }
  }
}

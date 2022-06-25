###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_vmware_v4pa_desktop_agent_detect.nasl 11420 2018-09-17 06:33:13Z cfischer $
#
# Vmware vRealize Operations Published Applications (V4PA) Desktop Agent Detection (Windows)
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.812788");
  script_version("$Revision: 11420 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-09-17 08:33:13 +0200 (Mon, 17 Sep 2018) $");
  script_tag(name:"creation_date", value:"2018-03-06 11:00:32 +0530 (Tue, 06 Mar 2018)");
  script_name("Vmware vRealize Operations Published Applications (V4PA) Desktop Agent Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Vmware V4PA Desktop Agent.

  The script logs in via smb, searches for 'vRealize Operations for Published
  Applications' in the registry, gets version and installation path information
  from the registry.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
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

if(!registry_key_exists(key:"SOFTWARE\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent")){
  exit(0);
}

if("x86" >< os_arch){
  key_list = make_list("SOFTWARE\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent");
}

else if("x64" >< os_arch){
  key_list = make_list("SOFTWARE\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent",
                       "SOFTWARE\Wow6432Node\VMware, Inc.\vRealize Operations for Published Apps\Desktop Agent");
}

foreach vmkey(key_list)
{
  vmVer = registry_get_sz(key:vmkey, item:"ProductVersion");
  vmPath = registry_get_sz(key:vmkey, item:"VMToolsPath");

  if(!vmPath){
    vmPath = "Couldn find the install location from registry";
  }

  if(vmVer)
  {
    set_kb_item(name:"vmware/V4PA/DesktopAgent/Win/Ver", value:vmVer);

    cpe = build_cpe(value:vmVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vrealize_operations_for_published_applications:");
    if(isnull(cpe))
      cpe = "cpe:/a:vmware:vrealize_operations_for_published_applications";

    if("x64" >< os_arch && "Wow6432Node" >!< vmkey)
    {
      set_kb_item(name:"vmware/V4PA/DesktopAgent64/Win/Ver", value:vmVer);

      cpe = build_cpe(value:vmVer, exp:"^([0-9.]+)", base:"cpe:/a:vmware:vrealize_operations_for_published_applications:x64:");
      if(isnull(cpe))
        cpe = "cpe:/a:vmware:vrealize_operations_for_published_applications:x64";
    }

    register_product(cpe:cpe, location:vmPath);

    log_message(data: build_detection_report(app: "vmware vRealize Operations for Published Apps Desktop Agent",
                                             version: vmVer,
                                             install: vmPath,
                                             cpe: cpe,
                                             concluded: vmVer));
  }
}
exit(0);

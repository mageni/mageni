###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_ca_mult_prdts_detect_win.nasl 10883 2018-08-10 10:52:12Z cfischer $
#
# CA Multiple Products Version Detection (Windows)
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http//www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.900966");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10883 $");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 12:52:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2011-11-15 12:44:36 +0530 (Tue, 15 Nov 2011)");
  script_name("CA Multiple Products Version Detection (Windows)");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed
  version of CA multiple products and sets the result in KB.");
  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("version_func.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\ComputerAssociates")){
  exit(0);
}

key = "SOFTWARE\ComputerAssociates\ProductInfoWSC";
ezavName = registry_get_sz(key:key, item:"DisplayName");
if("eTrust EZ Antivirus" >< ezavName)
{
  ezavVer = registry_get_sz(key:key, item:"ProductVersion");
  if(ezavVer){
    set_kb_item(name:"CA/Multiple_Products/Win/Installed", value:TRUE );
    set_kb_item(name:"CA/eTrust-EZ-AV/Win/Ver", value:ezavVer);

    register_and_report_cpe(app:ezavName, ver:ezavVer, base:"cpe:/a:ca:etrust_ez_antivirus:",
                            expr:"^([0-9.]+)");
  }
}

key = "SOFTWARE\ComputerAssociates\eTrust Suite Personal\";
caavName = registry_get_sz(key:key + "\av", item:"Name");
if("Anti-Virus" >< caavName)
{
  caavVer = registry_get_sz(key:key + "\av", item:"Version");
  if(caavVer){
    set_kb_item(name:"CA/Multiple_Products/Win/Installed", value:TRUE );
    set_kb_item(name:"CA/AV/Win/Ver", value:caavVer);

    register_and_report_cpe(app:caavName, ver:caavVer, base:"cpe:/a:ca:anti-virus:",
                            expr:"^([0-9.]+)");
  }
}

caissName = registry_get_sz(key:key + "\suite", item:"Name");
if("Internet Security Suite" >< caissName)
{
  caissVer = registry_get_sz(key:key + "\suite", item:"Version");
  if(caissVer){
    set_kb_item(name:"CA/Multiple_Products/Win/Installed", value:TRUE );
    set_kb_item(name:"CA/ISS/Win/Ver", value:caissVer);

    register_and_report_cpe(app:caissName, ver:caissVer, base:"cpe:/a:ca:internet_security_suite",
                            expr:"^([0-9.]+)");
  }
}

key = "SOFTWARE\CA\HIPSEngine";
cahipsVer = registry_get_sz(key:key, item:"Version");
if(cahipsVer){
  set_kb_item(name:"CA/Multiple_Products/Win/Installed", value:TRUE );
  set_kb_item(name:"CA/HIPS/Engine/Win/Ver", value:cahipsVer);
  log_message(data:"CA HIPS Engine version " + cahipsVer +
                     " was detected on the host");
}

if(registry_key_exists(key:"SOFTWARE\CA\HIPSManagementServer"))
{
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
  if(registry_key_exists(key:key))
  {
    foreach item (registry_enum_keys(key:key))
    {
      name = registry_get_sz(key:key + item, item:"DisplayName");
      if(eregmatch(pattern:"^CA HIPS Management Server", string:name))
      {
        hipsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(hipsVer != NULL)
        {
          set_kb_item(name:"CA/Multiple_Products/Win/Installed", value:TRUE );
          set_kb_item(name:"CA/HIPS/Server/Win/Ver", value:hipsVer);
          log_message(data:"CA HIPS Management Server version " + hipsVer +
                             " was detected on the host");
        }
      }
    }
  }
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
if(registry_key_exists(key:key))
{
  foreach item (registry_enum_keys(key:key))
  {
    if("CA Gateway Security" >< registry_get_sz(key:key + item,
                                                item:"DisplayName"))
    {
      cagsPath = registry_get_sz(key:key + item, item:"InstallLocation");
      cagsPath = cagsPath + "Bin";

      cagsVer = fetch_file_version(sysPath:cagsPath, file_name:"ManagerConsole.exe");
      if(cagsVer)
      {
        set_kb_item(name:"CA/Multiple_Products/Win/Installed", value:TRUE );
        set_kb_item(name:"CA/Gateway-Security/Win/Ver", value:cagsVer);

        register_and_report_cpe(app:"CA Gateway Security", ver:cagsVer, base:"cpe:/a:ca:gateway_security:",
                            expr:"^([0-9.]+)");
      }
    }
  }
}

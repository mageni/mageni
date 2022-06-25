###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_slysoft_prdts_detect.nasl 10883 2018-08-10 10:52:12Z cfischer $
#
# SlySoft Product(s) Version Detection
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.800391");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 10883 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-10 12:52:12 +0200 (Fri, 10 Aug 2018) $");
  script_tag(name:"creation_date", value:"2009-04-16 16:39:16 +0200 (Thu, 16 Apr 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("SlySoft Product(s) Version Detection");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"executable_version");
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_tag(name:"summary", value:"This script detects the installed version of SlySoft Product(s)
  and sets the result in KB.");
  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");
include("version_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

if(!registry_key_exists(key:"SOFTWARE\SlySoft"))
{
  if(!registry_key_exists(key:"SOFTWARE\Elaborate Bytes")){
    exit(0);
  }
}

anydvdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                 "\App Paths\AnyDVD.exe", item:"Path");
if(anydvdPath)
{
  anydvdVer = get_version(dllPath:anydvdPath + "\AnyDVD.exe", string:"prod", offs:332560);
  if(anydvdVer != NULL)
  {
    set_kb_item(name:"Slysoft/Products/Installed", value:TRUE);
    set_kb_item(name:"AnyDVD/Ver", value:anydvdVer);

    register_and_report_cpe(app:"AnyDVD", ver:anydvdVer, base:"cpe:/a:slysoft:anydvd:",
                            expr:"^([0-9.]+)", insloc:anydvdPath);
  }
}

clonedvdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                   "\App Paths\CloneDVD2.exe", item:"Path");
if(clonedvdPath)
{
  dvdVer = get_version(dllPath:clonedvdPath + "\CloneDVD2.exe", string:"prod", offs:332560);
  if(dvdVer != NULL)
  {
    set_kb_item(name:"Slysoft/Products/Installed", value:TRUE);
    set_kb_item(name:"CloneDVD/Ver", value:dvdVer);

    register_and_report_cpe(app:"CloneDVD", ver:dvdVer, base:"cpe:/a:slysoft:clonedvd:",
                            expr:"^([0-9.]+)", insloc:clonedvdPath);
  }
}
else
{
  clonedvdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                     "\App Paths\CloneDVD.exe", item:"Path");
  dvdVer = get_version(dllPath:clonedvdPath + "\CloneDVD.exe", string:"prod", offs:332560);
  if(dvdVer != NULL)
  {
    set_kb_item(name:"Slysoft/Products/Installed", value:TRUE);
    set_kb_item(name:"CloneDVD/Ver", value:dvdVer);

    register_and_report_cpe(app:"CloneDVD", ver:dvdVer, base:"cpe:/a:slysoft:clonedvd:",
                            expr:"^([0-9.]+)", insloc:clonedvdPath);
  }
}

clonecdPath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                  "\App Paths\CloneCD.exe", item:"Path");
if(clonecdPath)
{
  cdVer = get_version( dllPath:clonecdPath + "\CloneCD.exe", string:"prod", offs:332560);
  if(cdVer != NULL)
  {
    set_kb_item(name:"Slysoft/Products/Installed", value:TRUE);
    set_kb_item(name:"CloneCD/Ver", value:cdVer);

    register_and_report_cpe(app:"CloneCD", ver:cdVer, base:"cpe:/a:slysoft:clonecd:",
                            expr:"^([0-9.]+)", insloc:clonecdPath);
  }
}

drivePath = registry_get_sz(key:"SOFTWARE\Microsoft\Windows\CurrentVersion" +
                                "\App Paths\VCDPrefs.exe", item:"Path");
if(drivePath)
{
  driveVer = get_version( dllPath:drivePath + "\VCDPrefs.exe", string:"prod", offs:332560);
  if(driveVer != NULL)
  {
    set_kb_item(name:"Slysoft/Products/Installed", value:TRUE);
    set_kb_item(name:"VirtualCloneDrive/Ver", value:driveVer);

    register_and_report_cpe(app:"Virtual CloneDrive", ver:driveVer, base:"cpe:/a:slysoft:virtualclonedrive:",
                            expr:"^([0-9.]+)", insloc:drivePath);
  }
}
exit(0);

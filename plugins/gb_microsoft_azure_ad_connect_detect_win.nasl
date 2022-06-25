# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.815078");
  script_version("2019-05-18T06:07:35+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-05-18 06:07:35 +0000 (Sat, 18 May 2019)");
  script_tag(name:"creation_date", value:"2019-05-17 12:30:03 +0530 (Fri, 17 May 2019)");
  script_tag(name:"qod_type", value:"registry");
  script_name("Microsoft Azure AD Connect Detection (Windows)");

  script_tag(name:"summary", value:"Detects the installed version of
  Microsoft Azure AD Connect.

  The script logs in via smb, searches for Microsoft Azure AD Connect in the
  registry and gets the version from 'AzureADConnect.exe'.");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
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

key = "Software\Microsoft\Azure AD Connect";
if(!registry_key_exists(key:key)){
  exit(0);
}

appPath = registry_get_sz(key:key, item:"WizardPath");
if("AzureADConnect" >< appPath)
{
  appPath = ereg_replace(pattern:"\AzureADConnect.exe", replace:"", string:appPath);
  dllVer = fetch_file_version(sysPath:appPath, file_name:"AzureADConnect.exe");
  if(!dllVer)
    version = "unknown";

  set_kb_item(name:"microsoft/azureadconnect/win/detected", value:TRUE);

  cpe = build_cpe(value:dllVer, exp:"^([0-9.]+)", base:"cpe:/a:microsoft:azure_ad_connect:");
  if(!cpe)
    cpe = "cpe:/a:microsoft:azure_ad_connect";

  register_and_report_cpe(app:"Microsoft Azure AD Connect", ver:dllVer, concluded:"Microsoft Azure AD Connect " + dllVer,
                          cpename:cpe, insloc:appPath + "AzureADConnect.exe");
  exit(0);
}

exit(0);

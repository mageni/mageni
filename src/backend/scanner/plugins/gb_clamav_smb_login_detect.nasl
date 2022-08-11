# Copyright (C) 2009 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.800555");
  script_version("2022-03-01T12:03:40+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-03-02 11:03:54 +0000 (Wed, 02 Mar 2022)");
  script_tag(name:"creation_date", value:"2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)");
  script_name("ClamAV Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of ClamAV.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if("x86" >< os_arch)
  key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");

else if("x64" >< os_arch) {
  key_list = make_list("SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\",
                       "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\");
}

if(!key_list)
  exit(0);

foreach key(key_list) {

  foreach item(registry_enum_keys(key:key)) {

    clamName = registry_get_sz(key:key + item, item:"DisplayName");
    if("ClamWin" >< clamName || "ClamAV" >< clamName) {

      clamVer = eregmatch(pattern:"ClamWin Free Antivirus ([0-9.]+)", string:clamName);
      clamPath = "Couldn find the install location from registry";

      if(clamVer[1])
        clamVer = clamVer[1];
      else
        clamVer = registry_get_sz(key:key + item, item:"DisplayVersion");

      if(clamVer) {

        set_kb_item(name:"clamav/detected", value:TRUE);
        set_kb_item(name:"clamav/smb-login/detected", value:TRUE);

        cpe = build_cpe(value:clamVer, exp:"^([0-9.]+)", base:"cpe:/a:clamav:clamav:");
        if(!cpe)
          cpe = "cpe:/a:clamav:clamav";
      }
    }
  }

  if(!clamVer) {

    key = key + "Immunet Protect\";
    clamname = registry_get_sz(key:key, item:"DisplayName");

    if("ClamAV for Windows" >< clamname || "Immunet" >< clamname) {

      clamVer = registry_get_sz(key:key, item:"DisplayVersion");
      clamPath = registry_get_sz(key:key, item:"UninstallString");
      clamPath = clamPath - "uninstall.exe";

      if(clamVer) {

        set_kb_item(name:"clamav/detected", value:TRUE);
        set_kb_item(name:"clamav/smb-login/detected", value:TRUE);

        cpe = build_cpe(value:clamVer, exp:"^([0-9.]+)", base:"cpe:/a:clamav:clamav:");
        if(!cpe)
          cpe = "cpe:/a:clamav:clamav";
      }
    }
  }

  if(clamVer) {

    register_product(cpe:cpe, location:clamPath, port:0, service:"smb-login");

    log_message(data:build_detection_report(app:"ClamAV",
                                            version:clamVer,
                                            install:clamPath,
                                            cpe:cpe,
                                            concluded:clamVer),
                port:0);

  }
}

exit(0);

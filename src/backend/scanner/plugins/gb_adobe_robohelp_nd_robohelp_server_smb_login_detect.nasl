# SPDX-FileCopyrightText: 2013 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.803770");
  script_version("2023-11-24T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-11-24 05:05:36 +0000 (Fri, 24 Nov 2023)");
  script_tag(name:"creation_date", value:"2013-10-17 15:40:00 +0530 (Thu, 17 Oct 2013)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Adobe RoboHelp / Adobe RoboHelp Server Detection (Windows SMB Login)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2013 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://www.adobe.com/products/robohelp.html");
  script_xref(name:"URL", value:"https://www.adobe.com/products/robohelp/robohelp-server.html");

  script_tag(name:"summary", value:"SMB login-based detection of Adobe RoboHelp and Adobe RoboHelp
  Server.");

  script_tag(name:"qod_type", value:"registry");

  exit(0);
}

include("cpe.inc");
include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

if(!registry_key_exists(key:"SOFTWARE\Adobe\RoboHelp")) {
  if(!registry_key_exists(key:"SOFTWARE\Wow6432Node\Adobe\RoboHelp")) {
    exit(0);
  }
}

if(!os_arch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if("x86" >< os_arch) {
  key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

# nb: Presently Adobe RoboHelp 64bit application is not available
else if("x64" >< os_arch) {
  key = "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\";
}

if(!registry_key_exists(key:key))
  exit(0);

foreach item (registry_enum_keys(key:key)) {

  arhName = registry_get_sz(key:key + item, item:"DisplayName");
  if("Adobe RoboHelp" >< arhName) {

    arhInsPath = registry_get_sz(key:key + item, item:"DisplayIcon");
    if(arhInsPath) {
      arhInsPath = arhInsPath - "\ARPRobohelp.ico";
    } else {
      arhInsPath = "Could not find the install location from registry";
    }

    arhVer = registry_get_sz(key:key + item, item:"DisplayVersion");
    if(arhVer) {
      if("Server" >< arhName) {
        set_kb_item(name:"adobe/robohelp/server/detected", value:TRUE);
        set_kb_item(name:"adobe/robohelp/server/smb-login/detected", value:TRUE);
        register_and_report_cpe(app:arhName, ver:arhVer, concluded:arhVer, base:"cpe:/a:adobe:robohelp_server:", expr:"^([0-9.]+)", insloc:arhInsPath);
      } else {
        set_kb_item(name:"adobe/robohelp/detected", value:TRUE);
        set_kb_item(name:"adobe/robohelp/smb-login/detected", value:TRUE);
        set_kb_item(name:"adobe/robohelp/smb-login/installpath", value:arhInsPath);
        register_and_report_cpe(app:arhName, ver:arhVer, concluded:arhVer, base:"cpe:/a:adobe:robohelp:", expr:"^([0-9.]+)", insloc:arhInsPath);
      }
    }
  }
}

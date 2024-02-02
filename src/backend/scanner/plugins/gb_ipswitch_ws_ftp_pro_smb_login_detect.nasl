# SPDX-FileCopyrightText: 2010 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902170");
  script_version("2023-12-01T05:05:39+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-01 05:05:39 +0000 (Fri, 01 Dec 2023)");
  script_tag(name:"creation_date", value:"2010-04-23 17:57:39 +0200 (Fri, 23 Apr 2010)");
  script_name("Ipswitch WS_FTP Professional Detection (Windows SMB Login)");

  script_tag(name:"summary", value:"SMB login-based detection of Ipswitch WS_FTP Professional.");

  script_tag(name:"qod_type", value:"registry");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_xref(name:"URL", value:"https://docs.ipswitch.com/en/ws_ftp-professional.html");

  exit(0);
}

include("smb_nt.inc");
include("secpod_smb_func.inc");
include("cpe.inc");
include("host_details.inc");

if(!osArch = get_kb_item("SMB/Windows/Arch"))
  exit(0);

if(!registry_key_exists(key:"SOFTWARE\Ipswitch\WS_FTP") &&
   !registry_key_exists(key:"SOFTWARE\Wow6432Node\Ipswitch\WS_FTP")) {
  exit(0);
}

if("x86" >< osArch) {
  key_list = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\";
}

else if("x64" >< osArch) {
 key_list = make_list("SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                      "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\");
}

foreach key(key_list) {
  foreach item(registry_enum_keys(key:key)) {

    appName = registry_get_sz(key:key + item, item:"DisplayName");

    if("Ipswitch" >< appName || "WS_FTP" >< appName) {

      appAdd = registry_get_sz(key:key + item, item:"DisplayIcon");
      appLoc = registry_get_sz(key:key + item, item:"InstallLocation");

      if("ftppro" >< appAdd) {
        installed = TRUE;
      } else if(appLoc) {
        # nb: If version is fetched, file is present and so the Professional edition was found.
        checkpro = fetch_file_version(sysPath:appLoc, file_name:"wsftppro.exe");
        if(checkpro) {
          installed = TRUE;
        }
      } else {
        continue;
      }

      if(installed) {

        ipsVer = registry_get_sz(key:key + item, item:"DisplayVersion");
        if(ipsVer) {
          if(!appLoc){
            appLoc = "Could not find the install location from registry";
          }

          set_kb_item(name:"ipswitch/ws_ftp/professional/detected", value:TRUE);
          set_kb_item(name:"ipswitch/ws_ftp/professional/smb-login/detected", value:TRUE);

          cpe = build_cpe(value:ipsVer, exp:"^([0-9.]+)", base:"cpe:/a:ipswitch:ws_ftp:");
          if(!cpe)
            cpe = "cpe:/a:ipswitch:ws_ftp";

          if("x64" >< osArch && "Wow6432Node" >!< key) {

            cpe = build_cpe(value:ipsVer, exp:"^([0-9.]+)", base:"cpe:/a:ipswitch:ws_ftp:x64:");
            if(!cpe)
              cpe = "cpe:/a:ipswitch:ws_ftp:x64";
          }

          register_product(cpe:cpe, location:appLoc, port:0, service:"smb-login");
          log_message(data:build_detection_report(app:"Ipswitch WS_FTP Professional",
                                                  version:ipsVer,
                                                  install:appLoc,
                                                  cpe:cpe,
                                                  concluded:ipsVer),
                      port:0);
        }
      }
    }
  }
}

exit(0);

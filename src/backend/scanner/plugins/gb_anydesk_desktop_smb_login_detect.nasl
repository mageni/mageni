# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.813553");
  script_version("2024-02-07T05:05:18+0000");
  script_tag(name:"last_modification", value:"2024-02-07 05:05:18 +0000 (Wed, 07 Feb 2024)");
  script_tag(name:"creation_date", value:"2018-07-06 15:50:15 +0530 (Fri, 06 Jul 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("AnyDesk Desktop Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of AnyDesk Desktop for Windows.");

  exit(0);
}

include("smb_nt.inc");
include("host_details.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( ! os_arch )
  exit( 0 );

if( "x86" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" );
} else if( "x64" >< os_arch ) {
  key_list = make_list( "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\",
                        "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\" );
}

if( isnull( key_list ) )
  exit( 0 );

foreach key( key_list ) {
  foreach item( registry_enum_keys( key:key ) ) {

    app_name = registry_get_sz( key:key + item, item:"DisplayName" );
    # AnyDesk
    if( ! app_name || app_name !~ "AnyDesk" )
      continue;

    concluded = '\n    Registry Key: ' + key + item;
    concluded += '\n    DisplayName: ' + app_name;
    location = "unknown";
    version = "unknown";

    if( loc = registry_get_sz( key:key + item, item:"InstallLocation" ) )
      location = loc;

    # ad 8.0.6
    if( vers = registry_get_sz( key:key + item, item:"DisplayVersion" ) ) {
      if( vers=~ "ad [0-9.]+" ) {
        version = ereg_replace( pattern:"ad ", string:vers, replace:"" );
      } else if( vers=~ "[0-9.]+" ) {
        version = vers;
      }
      concluded += '\n    DisplayVersion: ' + vers;
    }

    set_kb_item( name:"anydesk/desktop/detected", value:TRUE );
    set_kb_item( name:"anydesk/desktop/smb-login/detected", value:TRUE );
    set_kb_item( name:"anydesk/desktop/smb-login/0/location", value:location );
    set_kb_item( name:"anydesk/desktop/smb-login/0/concluded", value:concluded );
    set_kb_item( name:"anydesk/desktop/smb-login/0/version", value:version );

    exit( 0 );
  }
}

exit( 0 );

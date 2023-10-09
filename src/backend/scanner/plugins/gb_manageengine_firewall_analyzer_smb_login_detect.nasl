# SPDX-FileCopyrightText: 2019 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107656");
  script_version("2023-08-18T16:09:48+0000");
  script_tag(name:"last_modification", value:"2023-08-18 16:09:48 +0000 (Fri, 18 Aug 2023)");
  script_tag(name:"creation_date", value:"2019-05-16 16:55:55 +0200 (Thu, 16 May 2019)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"registry");

  script_name("ManageEngine Firewall Analyzer Detection (Windows SMB Login)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2019 Greenbone AG");
  script_family("Product detection");
  script_dependencies("smb_reg_service_pack.nasl");
  script_mandatory_keys("SMB/WindowsVersion", "SMB/Windows/Arch");
  script_require_ports(139, 445);

  script_tag(name:"summary", value:"SMB login-based detection of ManageEngine Firewall Analyzer.");

  exit(0);
}

include("host_details.inc");
include("smb_nt.inc");
include("secpod_smb_func.inc");

os_arch = get_kb_item( "SMB/Windows/Arch" );
if( !os_arch )
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

    appName = registry_get_sz( key:key + item, item:"DisplayName" );
    if( ! appName || appName !~ "ManageEngine FireWall" )
      continue;

    concluded  = "Registry Key:   " + key + item + '\n';
    concluded += "DisplayName:    " + appName;
    location   = "unknown";
    version    = "unknown";
    build      = "unknown";

    loc = registry_get_sz( key:key + item, item:"InstallLocation" );
    if( loc )
      location = loc;

    infopath = location + "\logs\productInfoLog_0.txt";
    file_content = smb_read_file( fullpath:infopath, offset:0, count:3000 );

    ver = eregmatch( string:file_content, pattern:"Release Version\s*:\s*([0-9.]+)" );
    if( ver[1] ) {
      version = ver[1];
      concluded += '\n    File checked:   ' + infopath;
    }

    buildnumber = eregmatch( string:file_content, pattern:"Build Number\s*:\s*([0-9]+)" );
    if( buildnumber[1] )
      build = buildnumber[1];

    concluded += '\n    DisplayVersion: ' + version;
    concluded += '\n    Build Number:   ' + build;

    set_kb_item( name:"manageengine/products/detected", value:TRUE );
    set_kb_item( name:"manageengine/firewall_analyzer/smb/0/detected", value:TRUE );
  }

  set_kb_item( name:"manageengine/firewall_analyzer/smb/0/location", value:location );
  set_kb_item( name:"manageengine/firewall_analyzer/smb/0/version", value:version );
  set_kb_item( name:"manageengine/firewall_analyzer/smb/0/build", value:build );
  set_kb_item( name:"manageengine/firewall_analyzer/smb/0/concluded", value:concluded );

  exit( 0 );
}

exit( 0 );

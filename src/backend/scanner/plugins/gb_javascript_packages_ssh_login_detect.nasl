# SPDX-FileCopyrightText: 2018 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108456");
  script_version("2023-05-05T09:09:19+0000");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2018-08-08 13:22:34 +0200 (Wed, 08 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("JavaScript Packages Detection (Linux/Unix SSH Login)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2018 Greenbone AG");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"SSH login-based detection of JavaScript packages.");

  script_tag(name:"vuldetect", value:"Checks all found 'node_modules' directories for the existence
  of a 'package.json' and extracts information like the package name and the version of the package
  from it.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("ssh_func.inc");

function register_javascript_package( pkg, vers, location, concl ) {

  local_var pkg, vers, location, concl;

  set_kb_item( name:"javascript_package/" + pkg + "/ssh-login/detected", value:TRUE );
  set_kb_item( name:"javascript_package/" + pkg + "/ssh-login/location", value:location );
  set_kb_item( name:"javascript_package/" + pkg + "/" + location + "/ssh-login/version", value:vers );
  set_kb_item( name:"javascript_package/" + pkg + "/" + location + "/ssh-login/concluded", value:concl );
}

if( ! sock = ssh_login_or_reuse_connection() )
  exit( 0 );

if( ! locations = ssh_find_file( file_name:".*/node_modules/.*/package\.json", useregex:TRUE, sock:sock ) ) {
  ssh_close_connection();
  exit( 0 );
}

foreach location( locations ) {

  if( ! location = chomp( location ) )
    continue;

  if( ! buf = ssh_cmd( socket:sock, cmd:"cat " + location ) )
    continue;

  # nb: This is a quick way to remove nested JSON arrays and objects, as they might also contain name and version fields
  buf = ereg_replace( pattern:'"[^"]+"\\s*:\\s*\\[[^]]+\\][,]*', string:buf, replace:"" );
  buf = ereg_replace( pattern:'"[^"]+"\\s*:\\s*\\{[^}]+\\}[,]*', string:buf, replace:"" );

  if( buf ) {

    js_package_name = eregmatch( pattern:'"name"\\s*:\\s*"([^"]+)"', string:buf );
    js_package_version = eregmatch( pattern:'"version"\\s*:\\s*"([^"]+)"', string:buf );

    if( js_package_name[1] && js_package_version[1] ) {
      concluded = "Package name:    " + js_package_name[0];
      concluded += '\nPackage version: ' + js_package_version[0];
      register_javascript_package( pkg:js_package_name[1], vers:js_package_version[1], location:location, concl:concluded );
      found = TRUE;
    }
  }
}

if( found ) {
  set_kb_item( name:"javascript_packages/detected", value:TRUE );
  set_kb_item( name:"javascript_packages/ssh-login/detected", value:TRUE );
}

ssh_close_connection();
exit( 0 );

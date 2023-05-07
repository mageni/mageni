# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.170438");
  script_version("2023-05-05T09:09:19+0000");
  script_tag(name:"last_modification", value:"2023-05-05 09:09:19 +0000 (Fri, 05 May 2023)");
  script_tag(name:"creation_date", value:"2023-04-27 10:02:01 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("JavaScript Packages Detection Consolidation");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_javascript_packages_ssh_login_detect.nasl");
  script_mandatory_keys("javascript_packages/detected");

  script_tag(name:"summary", value:"Consolidation of JavaScript packages detections.");

  script_tag(name:"vuldetect", value:"Reports previously collected JavaScript packages in a
  structured way.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

if( ! get_kb_item( "javascript_packages/detected" ) )
  exit( 0 );

include("cpe.inc");
include("host_details.inc");

known_cpes = make_array( "vm2", "cpe:/a:vm2_project:vm2" );

report = ""; # nb: To make openvas-nasl-lint happy...
# nb: A detection is only possible if deployed in a "standard" way (means deployed / shipped with a standard "package.json" within a "node_modules" folder) and not "bundled" / packaged in e.g. a .exe file
foreach pkg( keys( known_cpes ) ) {
  foreach source( make_list( "ssh-login" ) ) {

    if( ! get_kb_item( "javascript_package/" + pkg + "/" + source + "/detected" ) )
      continue;

    if( ! locations = get_kb_list( "javascript_package/" + pkg + "/" + source + "/location" ) )
      continue;

    foreach location( locations ) {

      version = get_kb_item( "javascript_package/" + pkg + "/" + location + "/" + source + "/version" );
      concluded = get_kb_item( "javascript_package/" + pkg + "/" + location + "/" + source + "/concluded" );

      cpe = build_cpe( value:version, exp:"^([0-9a-z.]+)", base:known_cpes[pkg] + ":" );
      if( ! cpe )
        cpe = known_cpes[pkg];

      full_location = location;
      location = str_replace( string:location, find:"package.json", replace:"" );

      register_product( cpe:cpe, location:location, port:0, service:source );

      set_kb_item( name:"javascript_package/" + pkg + "/detected", value:TRUE );
      set_kb_item( name:"javascript_package/" + pkg + "/ssh-login/detected", value:TRUE );

      if( report )
        report += '\n\n';

      report += build_detection_report( app:pkg + " JavaScript package", version:version, install:location,
                                        cpe:cpe, concluded:concluded, concludedUrl:full_location );
    }
  }
}

if( report )
  log_message( port:0, data:report );

exit( 0 );

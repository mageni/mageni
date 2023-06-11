# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.126424");
  script_version("2023-06-02T09:09:16+0000");
  script_tag(name:"last_modification", value:"2023-06-02 09:09:16 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-09 13:32:07 +0000 (Tue, 09 May 2023)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("UltiDev Cassini Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("UltiDev_Cassini/banner");

  script_tag(name:"summary", value:"HTTP based detection of UltiDev Cassini.");

  script_xref(name:"URL", value:"http://ultidev.com/products/cassini/");

  exit(0);
}

CPE = "cpe:/a:ultidev:cassini:";

include("host_details.inc");
include("http_func.inc");
include("port_service_func.inc");
include("cpe.inc");
include("os_func.inc");

port = http_get_port( default: 80 );

banner = http_get_remote_headers( port: port );

if( concl = egrep( string: banner, pattern: "^[Ss]erver\s*:\s*UltiDev Cassini", icase: FALSE ) ) {

  set_kb_item( name: "ultidev_cassini/detected", value: TRUE );
  set_kb_item( name: "ultidev_cassini/http/detected", value: TRUE );

  concl = chomp( concl );
  version = "unknown";

  ver = eregmatch( string: banner, pattern: "UltiDev Cassini/([0-9.]+)", icase: FALSE );
  if( ! isnull( ver[1] ) )
    version = ver[1];

  os_register_and_report( os: "Microsoft Windows",
                          cpe: "cpe:/o:microsoft:windows",
                          banner_type: "UltiDev Cassini HTTP banner",
                          port: port,
                          banner: concl,
                          desc: "UltiDev Cassini Detection (HTTP)",
                          runs_key: "windows" );

  register_and_report_cpe( app: "UltiDev Cassini",
                           ver: version,
                           concluded: concl,
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );

# SPDX-FileCopyrightText: 2016 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140062");
  script_version("2023-04-05T10:10:37+0000");
  script_tag(name:"last_modification", value:"2023-04-05 10:10:37 +0000 (Wed, 05 Apr 2023)");
  script_tag(name:"creation_date", value:"2016-11-16 12:56:26 +0100 (Wed, 16 Nov 2016)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_name("Sophos Web Appliance (SWA) Detection (HTTP)");

  script_tag(name:"qod_type", value:"remote_banner");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2016 Greenbone AG");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"HTTP based detection of Sophos Web Appliance (SWA).");

  script_xref(name:"URL", value:"https://www.sophos.com/");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("host_details.inc");

port = http_get_port( default:443 );

buf = http_get_cache( port:port, item:"/" );

if( "<title>Sophos Web Appliance" >!< buf || ( "login_swa.jpg" >!< buf && "This tag is MANDATORY" >!< buf ) )
  exit( 0 );

install = "/";
version = "unknown";

set_kb_item( name:"sophos/web_appliance/detected", value:TRUE );
set_kb_item( name:"sophos/web_appliance/http/detected", value:TRUE );

cpe = "cpe:/a:sophos:web_appliance";

register_product( cpe:cpe, location:install, port:port, service:"www" );

report = build_detection_report( app:"Sophos Web Appliance (SWA)", version:version, install:install, cpe:cpe );

log_message( port:port, data:report );

exit( 0 );

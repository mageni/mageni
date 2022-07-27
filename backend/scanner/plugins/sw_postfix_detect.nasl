###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_postfix_detect.nasl 13461 2019-02-05 09:33:31Z cfischer $
#
# Postfix SMTP Server Detection
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111086");
  script_version("$Revision: 13461 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 10:33:31 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-02-04 17:00:00 +0100 (Thu, 04 Feb 2016)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Postfix SMTP Server Detection");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/banner/available");

  script_tag(name:"summary", value:"The script checks the SMTP server
  banner for the presence of Postfix.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("smtp_func.inc");
include("cpe.inc");

ports = smtp_get_ports();

foreach port( ports ) {

  banner = get_smtp_banner( port:port );

  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

  if( "ESMTP Postfix" >< banner || "Ubuntu/Postfix;" >< banner ||
    ( "Bye" >< quit && "Ok" >< noop && "Error: command not recognized" >< help && "Ok" >< rset ) ) {

    install = port + "/tcp";
    version = "unknown";

    ver = eregmatch( pattern:"220.*Postfix \(([0-9\.]+)\)", string:banner );
    if( ver[1] )
      version = ver[1];

    set_kb_item( name:"postfix/detected", value:TRUE );
    set_kb_item( name:"postfix/smtp/detected", value:TRUE );
    set_kb_item( name:"postfix/smtp/" + port + "/detected", value:version );

    cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:postfix:postfix:" );
    if( ! cpe )
      cpe = "cpe:/a:postfix:postfix";

    register_product( cpe:cpe, location:install, port:port, service:"smtp" );

    log_message( data:build_detection_report( app:"Postfix",
                                              version:version,
                                              install:install,
                                              cpe:cpe,
                                              concluded:banner ),
                                              port:port );
  }
}

exit( 0 );
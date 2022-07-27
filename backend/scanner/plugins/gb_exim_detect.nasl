###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_exim_detect.nasl 13461 2019-02-05 09:33:31Z cfischer $
#
# Exim Detection
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105189");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13461 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-05 10:33:31 +0100 (Tue, 05 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-01-29 15:29:06 +0100 (Thu, 29 Jan 2015)");
  script_name("Exim Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("smtpserver_detect.nasl");
  script_mandatory_keys("smtp/banner/available");

  script_tag(name:"summary", value:"The script sends a connection request to the
  server and attempts to extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("smtp_func.inc");
include("host_details.inc");
include("cpe.inc");

ports = smtp_get_ports();

foreach port( ports ) {

  banner = get_smtp_banner( port:port );

  quit = get_kb_item( "smtp/fingerprints/" + port + "/quit_banner" );
  noop = get_kb_item( "smtp/fingerprints/" + port + "/noop_banner" );
  help = get_kb_item( "smtp/fingerprints/" + port + "/help_banner" );
  rset = get_kb_item( "smtp/fingerprints/" + port + "/rset_banner" );

  if( "ESMTP Exim" >< banner || ( "closing connection" >< quit &&
      "OK" >< noop && "Commands supported:" >< help && "Reset OK" >< rset ) ) {

    vers = "unknown";
    install = port + "/tcp";

    version = eregmatch( pattern:'ESMTP Exim ([0-9.]+(_[0-9]+)?)', string:banner );
    if( version[1] )
      vers = version[1];

    if( "_" >< vers )
      vers = str_replace( string:vers, find:"_", replace:"." );

    set_kb_item( name:"exim/installed", value:TRUE );
    set_kb_item( name:"smtp/" + port + "/exim", value:vers );

    cpe = build_cpe( value:vers, exp:"^([0-9.]+)", base:"cpe:/a:exim:exim:" );
    if( ! cpe )
      cpe = "cpe:/a:exim:exim";

    register_product( cpe:cpe, location:install, port:port, service:"smtp" );

    log_message( data:build_detection_report( app:"Exim",
                                              version:vers,
                                              install:install,
                                              cpe:cpe,
                                              concluded:banner ),
                                              port:port );
  }
}

exit( 0 );
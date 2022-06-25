###############################################################################
# OpenVAS Vulnerability Test
# $Id: ntop_detect.nasl 13957 2019-03-01 09:46:54Z ckuersteiner $
#
# Ntop Detection
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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
  script_oid("1.3.6.1.4.1.25623.1.0.100256");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13957 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 10:46:54 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-08-23 12:14:46 +0200 (Sun, 23 Aug 2009)");
  script_tag(name:"cvss_base", value:"0.0");

  script_name("Ntop Detection");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl");
  script_require_ports("Services/www", 3000);
  script_mandatory_keys("ntop/banner");

  script_tag(name:"summary", value:"Detection of Ntop

  The script sends a connection request to the server and attempts to
  extract the version number from the reply.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_http_port( default:3000 );
buf = get_http_banner( port:port );

if( egrep( pattern:"Server: ntop" , string:buf, icase:TRUE ) ) {

  version = "unknown";
  install = "/";

  ver = eregmatch(string: buf, pattern: "Server: ntop/([0-9.]+)",icase:TRUE);

  if( ! isnull( ver[1] ) )
    version = ver[1];

  set_kb_item( name:"ntop/installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ntop:ntop:" );
  if( !cpe )
    cpe = 'cpe:/a:ntop:ntop';

  register_product( cpe:cpe, location:install, port:port );

  log_message( data:build_detection_report( app:"Ntop",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
               port:port );
}

exit( 0 );

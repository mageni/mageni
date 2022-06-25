###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_autonomic_controls_http_detect.nasl 13795 2019-02-20 15:20:14Z cfischer $
#
# Autonomic Controls Detection (HTTP)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net>
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, https://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.113242");
  script_version("$Revision: 13795 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-20 16:20:14 +0100 (Wed, 20 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-08-07 10:33:33 +0200 (Tue, 07 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Autonomic Controls Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"Detection for Autonomic Controls devices using HTTP.");

  script_xref(name:"URL", value:"http://www.autonomic-controls.com/products/");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");

port = get_http_port( default: 80 );
banner = get_http_banner( port: port );

if( banner && banner =~ 'Autonomic Controls' ) {

  set_kb_item( name: "autonomic_controls/detected", value: TRUE );
  set_kb_item( name: "autonomic_controls/http/port", value: port );

  ver = eregmatch( string: banner, pattern: 'Autonomic Controls/([0-9.]+)', icase: TRUE );
  if( ! isnull( ver[1] ) ) {
    set_kb_item( name: "autonomic_controls/http/version", value: ver[1] );
    set_kb_item( name: "autonomic_controls/http/concluded", value: ver[0] );
  }
}

exit( 0 );
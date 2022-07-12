###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_emc_data_domain_detect_www.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# EMC Data Domain Detection (HTTP)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140145");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-01 12:25:05 +0100 (Wed, 01 Feb 2017)");
  script_name("EMC Data Domain Detection (HTTP)");

  script_tag(name:"summary", value:"This script performs HTTP based detection of EMC Data Domain.");

  script_tag(name:"qod_type", value:"package");

  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port( default:80 );

url = '/ddem/login/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( 'companyName":"Data Domain"' >!< buf || "DD System Manager Login" >!< buf ) exit( 0 );

set_kb_item( name:"emc/data_domain/installed", value:TRUE );

# ,"appVersion":"6.0.0.9-544198",
vb = eregmatch( pattern:',"appVersion":"([0-9.]+[^-]+)-([0-9]+)"', string:buf );

if( ! isnull( vb[1] ) )
  replace_kb_item( name:"emc/data_domain/version/http", value:vb[1] );

if( ! isnull( vb[2] ) )
  replace_kb_item( name:"emc/data_domain/build/http", value:vb[2] );

log_message( port:port, data:"The EMC Data Domain System Manager is running at this port." );

exit( 0 );


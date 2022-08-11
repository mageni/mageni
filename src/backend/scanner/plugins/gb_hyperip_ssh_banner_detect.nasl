###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hyperip_ssh_banner_detect.nasl 13571 2019-02-11 11:00:12Z cfischer $
#
# NetEx HyperIP Detection (SSH-Banner)
#
# Authors:
# Adrian Steins <adrian.steins@greenbone.net>
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108350");
  script_version("$Revision: 13571 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 12:00:12 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2018-02-26 12:49:56 +0100 (Mon, 26 Feb 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("NetEx HyperIP Detection (SSH-Banner)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/server_banner/available");

  script_tag(name:"summary", value:"This script performs SSH banner based detection of a NetEx HyperIP
  virtual appliance.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("host_details.inc");

port = get_ssh_port( default:22 );

#                            PRIVATE/PROPRIETARY/SECURE
#                       NO DISCLOSURE OUTSIDE THIS DOMAIN
#                          EXCEPT BY WRITTEN AGREEMENT.
#                    MUST BE SECURELY STORED WHEN NOT IN USE.
#                      UNAUTHORIZED ACCESS TO, OR MISUSE OF
#                       THIS SYSTEM OR DATA IS PROHIBITED.
#                   THIS SYSTEM MAY BE PERIODICALLY MONITORED
#                                AND/OR AUDITED.
#
#HyperIP 6.1.1 example.com 127.0.0.1 127.0.0.2
banner = get_kb_item( "SSH/textbanner/" + port );
if( ! banner || ! egrep( pattern:"^HyperIP", string:banner ) ) exit( 0 );

version = "unknown";

vers = eregmatch( pattern:"HyperIP ([0-9.]+)", string:banner );
if( vers[1] ) {
  version = vers[1];
  set_kb_item( name:"hyperip/ssh-banner/" + port + "/concluded", value:vers[0] );
}

set_kb_item( name:"hyperip/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-banner/detected", value:TRUE );
set_kb_item( name:"hyperip/ssh-banner/port", value:port );
set_kb_item( name:"hyperip/ssh-banner/" + port + "/version", value:version );

exit( 0 );
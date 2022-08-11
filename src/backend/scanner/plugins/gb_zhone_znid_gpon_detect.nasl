###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_zhone_znid_gpon_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# ZHONE ZNID GPON Device Detection (Telnet)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105404");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-10-15 11:45:06 +0200 (Thu, 15 Oct 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("ZHONE ZNID GPON Device Detection (Telnet)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/zhone/znid_gpon/detected");

  script_tag(name:"summary", value:"The script performs Telnet based detection of ZHONE ZNID GPON devices");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("host_details.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );
if( ! banner || "Model: ZNID-GPON" >!< banner )
  exit( 0 );

set_kb_item( name:"zhone/installed", value:TRUE );

vers = "unknown";
install = port + "/tcp";
cpe = "cpe:/o:zhone_technologies:gpon_firmware";

version = eregmatch( pattern:'Release: ([^\r\n]+)', string:banner );
if( ! isnull( version[1] ) ) {
  vers = version[1];
  cpe += ':' + vers;
}

model = eregmatch( pattern:'Model: ZNID-GPON-([^ ]+)', string:banner );
if( ! isnull( model[1] ) ) {
  mod = model[1];
  replace_kb_item( name:"zhone/model", value:mod );
}

register_product( cpe:cpe, location:install, port:port, service:"telnet" );

log_message( data:build_detection_report( app:"Zhone ZNID-GPON " + mod,
                                          version:vers,
                                          install:install,
                                          cpe:cpe,
                                          concluded:banner,
                                          extra:"Model: " + mod ),
                                          port:port );
exit( 0 );
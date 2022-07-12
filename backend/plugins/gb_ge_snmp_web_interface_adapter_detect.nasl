###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ge_snmp_web_interface_adapter_detect.nasl 13624 2019-02-13 10:02:56Z cfischer $
#
# GE SNMP/Web Interface Adapter Version Detection
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
#
# Copyright:
# Copyright (C) 2016 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.807076");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_version("$Revision: 13624 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-13 11:02:56 +0100 (Wed, 13 Feb 2019) $");
  script_tag(name:"creation_date", value:"2016-03-01 14:45:32 +0530 (Tue, 01 Mar 2016)");
  script_name("GE SNMP/Web Interface Adapter Version Detection");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);
  script_mandatory_keys("telnet/ge/snmp_web_iface_adapter/detected");

  script_tag(name:"summary", value:"Detection of installed version
  of SNMP/Web Adapter.

  The script performs Telnet based detection of SNMP/Web Adapter");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("telnet_func.inc");
include("misc_func.inc");
include("cpe.inc");
include("host_details.inc");

port = get_telnet_port( default:23 );
banner = get_telnet_banner( port:port );

if( banner && banner =~ "GE.*SNMP/Web Interface" && "UPS" >< banner ) {

  version = "unknown";
  install = "/";

  ver = eregmatch( pattern:'SNMP/Web Interface Ver.([0-9.]+)', string:banner );
  if( ver[1] ) version = ver[1];

  set_kb_item( name:"SNMP/Web/Adapter/telnet/version", value:version );
  set_kb_item( name:"SNMP/Web/Adapter/Installed", value:TRUE );

  cpe = build_cpe( value:version, exp:"^([0-9.]+)", base:"cpe:/a:ge:ups_snmp_web_adapter_firmware:" );
  if( ! cpe )
    cpe = "cpe:/a:ge:ups_snmp_web_adapter_firmware";

  register_product( cpe:cpe, location:install, port:port, service:"telnet" );

  log_message( data:build_detection_report( app:"SNMP/Web Adapter",
                                            version:version,
                                            install:install,
                                            cpe:cpe,
                                            concluded:ver[0] ),
                                            port:port );
}

exit( 0 );
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hpe_officeconnect_switch_snmp_detect.nasl 11885 2018-10-12 13:47:20Z cfischer $
#
# HPE OfficeConnect Switch Detection (SNMP)
#
# Authors:
# Jan Philipp Schulte <jan.schulte@greenbone.net
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

if( description )
{
  script_oid("1.3.6.1.4.1.25623.1.0.113257");
  script_version("$Revision: 11885 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2018-08-30 09:54:55 +0200 (Thu, 30 Aug 2018)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("HPE OfficeConnect Switch Detection (SNMP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  script_tag(name:"summary", value:"Detects if the target is an HPE OfficeConnect Switch
  and if so, tries to gather information about the firmware version.");

  script_xref(name:"URL", value:"https://www.hpe.com/de/de/product-catalog/networking/networking-switches.filters-facet_productline_url:officeconnect.hits-12.html");

  exit(0);
}

CPE = "cpe:/h:hpe:officeconnect_switch:";

include( "host_details.inc" );
include( "snmp_func.inc" );
include( "cpe.inc" );

port = get_snmp_port( default: 161 );
sysdesc = get_snmp_sysdesc( port: port );
if( ! sysdesc || sysdesc !~ 'HP[E]?( OfficeConnect)?( Switch)? [0-9]{4}' ) exit( 0 );

set_kb_item( name: "hpe/officeconnect_switch/detected", value: TRUE );
set_kb_item( name: "hpe/officeconnect_switch/snmp/port", value: TRUE );

fw_version = "unknown";
model = "unknown";

model_match = eregmatch( string: sysdesc, pattern: 'HP[E]?( OfficeConnect)?( Switch)? ([^,\r\n]+)', icase: TRUE );
if( ! isnull( model_match[3] ) ) {
  model = model_match[3];
  set_kb_item( name: "hpe/officeconnect_switch/model", value: model );
}

vers = eregmatch( string: sysdesc, pattern: 'HP[E]?[^,]+,[ ]?[^0-9]*([0-9.]+)', icase: TRUE );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  set_kb_item( name: "hpe/officeconnect_switch/version", value: version );
}

register_and_report_cpe( app: "HPE OfficeConnect Switch",
                         ver: version,
                         concluded: vers[0],
                         base: CPE,
                         expr: '([0-9.]+)',
                         regPort: port );

exit( 0 );

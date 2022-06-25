# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.112772");
  script_version("2020-06-30T14:06:48+0000");
  script_tag(name:"last_modification", value:"2020-07-06 10:39:35 +0000 (Mon, 06 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-06-30 13:23:11 +0000 (Tue, 30 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("SATO Printer Detection (SNMP)");

  script_tag(name:"summary", value:"SNMP based detection of SATO printers.");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_snmp_sysdesc.nasl");
  script_require_udp_ports("Services/udp/snmp", 161);
  script_mandatory_keys("SNMP/sysdesc/available");

  exit(0);
}

include("snmp_func.inc");

port = snmp_get_port( default: 161 );

sysdesc = snmp_get_sysdesc( port: port );
if( ! sysdesc )
  exit( 0 );

# SATO CL6NX-J 203dpi
# SATO LR4NX-FA 305dpi
if( sysdesc =~ "^SATO " ) {
  set_kb_item( name: "sato_printer/detected", value: TRUE );
  set_kb_item( name: "sato_printer/snmp/detected", value: TRUE );
  set_kb_item( name: "sato_printer/snmp/port", value: port );
  set_kb_item( name: "sato_printer/snmp/" + port + "/concluded", value: sysdesc );

  mod = eregmatch( pattern: "SATO ([^\r\n]+)", string: sysdesc );
  if( ! isnull( mod[1] ) ) {
    set_kb_item( name: "sato_printer/snmp/" + port + "/model", value: mod[1] );
  }

  exit( 0 );
}

exit( 0 );

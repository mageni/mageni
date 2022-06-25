# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108661");
  script_version("2019-10-08T14:13:49+0000");
  script_tag(name:"last_modification", value:"2019-10-08 14:13:49 +0000 (Tue, 08 Oct 2019)");
  script_tag(name:"creation_date", value:"2019-10-08 13:56:07 +0000 (Tue, 08 Oct 2019)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"Workaround");

  script_name("PPTP Server/Device Compromised");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("pptp_detect.nasl");
  script_mandatory_keys("pptp/hostname/detected");

  script_tag(name:"summary", value:"The remote PPTP Server/Device might have been compromised
  by an attacker or a worm.");

  script_tag(name:"impact", value:"The device might be used by an attacker as a jump host to get access to an internal
  network. It also might be part of a botnet.");

  script_tag(name:"vuldetect", value:"Checks the device hostname previously gathered via the PPTP Protocol.");

  script_tag(name:"solution", value:"A factory reset of the device is required. Afterwards all available updates should
  be applied and a strong password chosen for the device access.

  Please contact the vendor if further steps are required to clean up and protect the device.");

  exit(0);
}

include("misc_func.inc");

if( ! port = get_port_for_service( default:1723, proto:"pptp" ) )
  exit( 0 );

if( ! hostname = get_kb_item( "pptp/" + port + "/hostname/detected" ) )
  exit( 0 );

# Hostname:         HACKED
# Hostname:         hAcKeD
if( egrep( string:hostname, pattern:"HACKED", icase:TRUE ) ) {
  report  = 'The device reports the following hostname via the PPTP Protocol which indicates ';
  report += 'that the device was compromised by an attacker or a worm:\n\n' + hostname;
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

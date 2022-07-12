# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.117244");
  script_version("2021-03-12T12:00:12+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2021-03-15 11:31:29 +0000 (Mon, 15 Mar 2021)");
  script_tag(name:"creation_date", value:"2021-03-12 11:29:29 +0000 (Fri, 12 Mar 2021)");
  script_name("OpenSSL Detection (SSH)");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("ssh/openssl/detected");

  script_tag(name:"summary", value:"SSH based detection of OpenSSL.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("ssh_func.inc");
include("port_service_func.inc");

port = ssh_get_port( default:22 );
banner = ssh_get_serverbanner( port:port );

if( banner && concl = egrep( string:banner, pattern:"^SSH-.+OpenSSL", icase:TRUE ) ) {

  concl = chomp( concl );
  version = "unknown";
  install = port + "/tcp";

  # SSH-2.0-OpenSSH_7.2p2 Ubuntu-4ubuntu2.10, OpenSSL 1.0.2g  1 Mar 2016
  # SSH-2.0-OpenSSH_5.3p1, OpenSSL 1.0.1e-fips 11 Feb 2013
  # SSH-1.99-OpenSSH_5.1p1, OpenSSL 0.9.8h 28 May 2008
  # SSH-2.0-OpenSSH_4.3p2, OpenSSL 0.9.8e-fips-rhel5 01 Jul 2008
  # SSH-2.0-OpenSSL 1.0.2k-fips
  # SSH-2.0-SSH-2.0-OpenSSH_7.4p1 Raspbian-10+deb9u4, OpenSSL 1.0.2q  20 Nov 2018
  # SSH-2.0-OpenSSH_4.2, SSH protocols 1.5/2.0, OpenSSL 0x0090802f
  vers = eregmatch( pattern:"SSH-.+OpenSSL ([0-9.a-z]+)", string:concl, icase:TRUE );
  if( vers[1] && "OpenSSL 0x" >!< vers[0] ) # nb: 0x00 above isn't a real version.
    version = vers[1];

  set_kb_item( name:"openssl/detected", value:TRUE );
  set_kb_item( name:"openssl/ssh/" + port + "/installs", value:port + "#---#" + install + "#---#" + version + "#---#" + concl );
  set_kb_item( name:"openssl/ssh/detected", value:TRUE );
  set_kb_item( name:"openssl/ssh/port", value:port );
}

exit( 0 );

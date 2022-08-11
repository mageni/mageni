# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108716");
  script_version("2020-03-02T11:38:26+0000");
  script_tag(name:"last_modification", value:"2020-03-03 11:02:28 +0000 (Tue, 03 Mar 2020)");
  script_tag(name:"creation_date", value:"2020-03-02 11:09:59 +0000 (Mon, 02 Mar 2020)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Apache JServ Protocol (AJP) Public WAN (Internet) Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_jserv_ajp_detect.nasl", "global_settings.nasl");
  script_require_ports("Services/ajp13", 8009);
  script_require_keys("apache/ajp/detected", "keys/is_public_addr");

  script_xref(name:"URL", value:"https://lists.apache.org/thread.html/r7c6f492fbd39af34a68681dbbba0468490ff1a97a1bd79c6a53610ef%40%3Cannounce.tomcat.apache.org%3E");

  script_tag(name:"summary", value:"The script checks if the target host is running a service supporting
  the Apache JServ Protocol (AJP) accessible from a public WAN (Internet).");

  script_tag(name:"insight", value:"When using the Apache JServ Protocol (AJP), care must be taken when
  trusting incoming connections to Apache Tomcat. Tomcat treats AJP connections as having higher trust than,
  for example, a similar HTTP connection. If such connections are available to an attacker, they can
  be exploited in ways that may be surprising (e.g. bypassing security checks, bypassing user authentication among others).");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running a service supporting
  the Apache JServ Protocol (AJP) accessible from a public WAN (Internet).");

  script_tag(name:"solution", value:"Only allow access to the AJP service from trusted sources / networks.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("misc_func.inc");
include("network_func.inc");

if( ! is_public_addr() )
  exit( 0 );

port = get_port_for_service( default:8009, proto:"ajp13" );

if( ! get_kb_item( "apache/ajp/" + port + "/detected" ) )
  exit( 99 );

security_message( port:port );
exit( 0 );

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

CPE = "cpe:/a:sphinxsearch:sphinxsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108621");
  script_version("2019-08-27T09:12:56+0000");
  script_tag(name:"last_modification", value:"2019-08-27 09:12:56 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"creation_date", value:"2019-08-27 08:54:09 +0000 (Tue, 27 Aug 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sphinx search server Public WAN (Internet) Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("sw_sphinxsearch_detect.nasl", "global_settings.nasl");
  script_mandatory_keys("sphinxsearch/noauth");
  script_exclude_keys("keys/islocalhost", "keys/islocalnet", "keys/is_private_addr");

  script_xref(name:"URL", value:"https://www.bsi.bund.de/EN/Topics/IT-Crisis-Management/CERT-Bund/CERT-Reports/HOWTOs/Open-Sphinx-Server/open-Sphinx-server_node.html");

  script_tag(name:"summary", value:"The script checks if the target host is running an Sphinx search
  server accessible from a public WAN (Internet).");

  script_tag(name:"impact", value:"This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration.");

  script_tag(name:"vuldetect", value:"Evaluate if the target host is running an Sphinx search
  server accessible from a public WAN (Internet).");

  script_tag(name:"solution", value:"Only allow access to the Sphinx search server from trusted sources.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

include("host_details.inc");
include("network_func.inc");

if( islocalnet() || islocalhost() || is_private_addr() )
  exit( 0 );

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

if( ! get_kb_item( "sphinxsearch/" + port + "/noauth" ) )
  exit( 99 );

security_message( port:port );
exit( 0 );
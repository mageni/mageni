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
  script_oid("1.3.6.1.4.1.25623.1.0.113671");
  script_version("2020-04-09T09:11:31+0000");
  script_tag(name:"last_modification", value:"2020-04-09 11:12:54 +0000 (Thu, 09 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-09 11:00:00 +0100 (Thu, 09 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"remote_banner");

  script_name("Puppet Detection (HTTP)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_get_http_banner.nasl");
  script_mandatory_keys("puppet/banner");

  script_tag(name:"summary", value:"Checks whether Puppet is present on
  the target system and if so, tries to figure out the installed version.");

  script_xref(name:"URL", value:"https://puppet.com/docs/puppet/latest/puppet_index.html");

  exit(0);
}

# nb: This is a different product than "Puppet Enterprise"

CPE = "cpe:/a:puppet:puppet:";

include( "host_details.inc" );
include( "http_func.inc" );
include( "cpe.inc" );

port = get_http_port( default: 80 );

buf = get_http_banner( port: port );

if( buf =~ "X-Puppet-Version\s*:" ) {
  set_kb_item( name: "puppet/detected", value: TRUE );

  version = "unknown";

  ver = eregmatch( string: buf, pattern: "X-Puppet-Version\s*:\s*([0-9.]+)" );
  if( ! isnull( ver[1] ) )
    version = ver[1];

  register_and_report_cpe( app: "Puppet",
                           ver: version,
                           concluded: ver[0],
                           base: CPE,
                           expr: "([0-9.]+)",
                           insloc: port + "/tcp",
                           regPort: port,
                           regService: "www" );
}

exit( 0 );

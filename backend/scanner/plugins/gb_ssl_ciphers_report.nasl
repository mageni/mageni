# Copyright (C) 2014 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
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
  script_oid("1.3.6.1.4.1.25623.1.0.802067");
  script_version("2022-02-18T09:01:14+0000");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-02-18 09:01:14 +0000 (Fri, 18 Feb 2022)");
  script_tag(name:"creation_date", value:"2014-03-06 17:20:28 +0530 (Thu, 06 Mar 2014)");
  script_name("SSL/TLS: Report Supported Cipher Suites");
  script_category(ACT_GATHER_INFO);
  script_family("SSL and TLS");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("secpod_ssl_ciphers.nasl");
  script_mandatory_keys("secpod_ssl_ciphers/supported_ciphers", "secpod_ssl_ciphers/started", "ssl_tls/port");

  # nb: This VT had a script preference with the id:1, newly added preferences in the future needs to
  # choose id:2 or higher to avoid conflicts with that removed preference still kept in gvmd database.

  script_tag(name:"summary", value:"This routine reports all SSL/TLS cipher suites accepted by a
  service.

  As the VT 'SSL/TLS: Check Supported Cipher Suites' (OID: 1.3.6.1.4.1.25623.1.0.900234) might run
  into a timeout the actual reporting of all accepted cipher suites takes place in this VT instead.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("ssl_funcs.inc");
include("gb_print_ciphers.inc");

if( ! port = tls_ssl_get_port() )
  exit( 0 );

report = print_cipherlists( port:port, strengths:"strong,medium,weak,null,anon", negative:1 );

if( report )
  log_message( port:port, data:report );

exit( 0 );

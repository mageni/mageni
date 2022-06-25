# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from the referenced
# advisories, and are Copyright (C) by the respective right holder(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.108760");
  script_version("2020-04-29T09:12:44+0000");
  script_tag(name:"last_modification", value:"2020-04-29 09:12:44 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"creation_date", value:"2020-04-29 07:29:36 +0000 (Wed, 29 Apr 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Cloudflare '/cdn-cgi/trace' Debug / Trace Output Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "httpver.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 443);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"The remote host is exposing the '/cdn-cgi/trace' endpoint of
  Cloudflare.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:443 );

url = "/cdn-cgi/trace";
buf = http_get_cache( item:url, port:port );
if( buf && buf =~ "^HTTP/1\.[01] 200" && buf =~ "content-type\s*:\s*text/plain" && egrep( string:buf, pattern:"^visit_scheme=.+", icase:FALSE ) ) {
  report = "Exposed URL: " + http_report_vuln_url( port:port, url:url, url_only:TRUE );
  log_message( port:port, data:report );
}

exit( 0 );

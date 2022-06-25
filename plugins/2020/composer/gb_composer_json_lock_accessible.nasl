# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.108761");
  script_version("2020-05-04T05:55:46+0000");
  script_tag(name:"last_modification", value:"2020-05-04 05:55:46 +0000 (Mon, 04 May 2020)");
  script_tag(name:"creation_date", value:"2020-05-04 05:15:57 +0000 (Mon, 04 May 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Composer composer.lock / composer.json Accessible");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://getcomposer.org/");

  script_tag(name:"summary", value:"The remote host is exposing a 'composer.json' and / or 'composer.lock'
  file of the Composer dependency manager for PHP. This file(s) might expose some information about the
  structure of the web application and the installed software / dependencies on the remote host.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = http_get_port( default:80 );
if( ! http_can_host_php( port:port ) )
  exit( 0 );

files = make_list( "/composer.json", "/composer.lock", "/composer.json-dist", "/composer.json.dist" );
report = 'The following files have been identified:\n';
found = FALSE;

host = http_host_name( dont_add_port:TRUE );

foreach dir( make_list_unique( "/", "/.composer", http_cgi_dirs( port:port ) ) ) {

  if( dir == "/" )
    dir = "";

  foreach file( files ) {

    url = dir + file;
    buf = http_get_cache( item:url, port:port );
    if( ! buf || buf !~ "^HTTP/1\.[01] 200" || buf !~ "content-type\s*:\s*application/(octet-stream|json)" )
      continue;

    body = http_extract_body_from_response( data:buf );
    if( ! body )
      continue;

    # for example:
    #
    # "description": "mydescription",
    #
    # "require-dev": {
    #            "phpunit/phpunit": "3.7.*"
    #        },
    #
    # "license": [
    #            "MIT"
    #        ],
    if( body =~ "^\s*\{" && egrep( string:body, pattern:'^\\s*"(description|require(-dev)?|license|packages)"\\s*:\\s*["{[]', icase:FALSE ) ) {
      report += '\n' + http_report_vuln_url( port:port, url:url, url_only:TRUE );
      set_kb_item( name:"composer_file/" + host + "/locations", value:url );
      set_kb_item( name:"composer_file/" + host + "/" + url + "/content", value:body );
      found = TRUE;
    }
  }
}

if( found ) {
  set_kb_item( name:"composer_file/detected", value:TRUE );
  log_message( port:port, data:report );
}

exit( 0 );

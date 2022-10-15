# Copyright (C) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105262");
  script_version("2022-10-10T10:12:14+0000");
  script_tag(name:"last_modification", value:"2022-10-10 10:12:14 +0000 (Mon, 10 Oct 2022)");
  script_tag(name:"creation_date", value:"2015-04-22 13:23:32 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");

  script_tag(name:"qod_type", value:"package");

  script_name("Palo Alto Device Detection (XML-API)");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Product detection");
  script_dependencies("gb_paloalto_panos_http_detect.nasl");
  script_mandatory_keys("palo_alto/http/detected");

  script_tag(name:"summary", value:"XML-API based detection of the Palo Alto devices.");

  script_add_preference(name:"API Username: ", value:"", type:"entry", id:1);
  script_add_preference(name:"API Password: ", value:"", type:"password", id:2);

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("url_func.inc");

function exit_and_report_fail( port, reason ) {

  local_var port, reason;

  set_kb_item( name:"palo_alto/xml-api/" + port + "/fail_reason", value:reason );
  exit( 0 );
}

if( ! port = get_kb_item( "palo_alto/http/port" ) )
  exit( 0 );

user = script_get_preference( "API Username: ", id:1 );
pass = script_get_preference( "API Password: ", id:2 );

if( ! user || ! pass ) {
  if( ! user && pass )
    exit_and_report_fail( port:port, reason:"API Password provided but API Username missing." );

  if( user && ! pass )
    exit_and_report_fail( port:port, reason:"API Username provided but API Password missing." );

  exit( 0 );
}

url = "/api/?type=keygen&user=" + user + "&password=" + pass;

req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "success" >!< res || "<key>" >!< res ) {
  if( reason = egrep( pattern:"<msg>.*</msg>", string:res ) )
    exit_and_report_fail( port:port, reason:reason );

  exit_and_report_fail( port:port, reason:"Unknown error occurred while trying to generate an Access Key via '/api/?type=keygen'." );
}

match = eregmatch( pattern:"<key>([^<]+)</key>", string:res );
if( isnull( match[1] ) )
  exit_and_report_fail( port:port, reason:"Failed to fetch generated Access Key from '/api/?type=keygen'." );

key = urlencode( str:match[1] );

url = "/api/?type=op&cmd=%3Cshow%3E%3Csystem%3E%3Cinfo%3E%3C%2Finfo%3E%3C%2Fsystem%3E%3C%2Fshow%3E&key=" + key;
req = http_get( port:port, item:url );
res = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );

if( "success" >!< res || "<result>" >!< res ) {
  if( reason = egrep( pattern:"<msg>.*</msg>", string:res ) )
    exit_and_report_fail( port:port, reason:reason );

  exit_and_report_fail( port:port, reason:"Unknown error occurred while trying to access '/api/?type=op' via the previously generated Access Key." );
}

model = "unknown";
version = "unknown";

set_kb_item( name:"palo_alto/detected", value:TRUE );
set_kb_item( name:"palo_alto/xml-api/detected", value:TRUE );
set_kb_item( name:"palo_alto/xml-api/port", value:port );
set_kb_item( name:"palo_alto/xml-api/" + port + "/concludedUrl",
             value:http_report_vuln_url( port:port, url:"/api/", url_only:TRUE ) );

# <model>PA-VM</model>
mod = eregmatch( pattern:"<model>([^<]+)</model>", string:res );
if( ! isnull( mod[1] ) ) {
  model = mod[1];
  concluded = '\n  ' + mod[0];
}

# <sw-version>10.0.0</sw-version>
vers = eregmatch( pattern:"<sw-version>([^<]+)</sw-version>", string:res );
if( ! isnull( vers[1] ) ) {
  version = vers[1];
  concluded += '\n  ' + vers[0];
}

if( concluded )
  set_kb_item( name:"palo_alto/xml-api/" + port + "/concluded", value:concluded );

set_kb_item( name:"palo_alto/xml-api/" + port + "/model", value:model );
set_kb_item( name:"palo_alto/xml-api/" + port + "/version", value:version );

exit( 0 );

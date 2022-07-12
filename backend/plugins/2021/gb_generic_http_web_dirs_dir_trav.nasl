# Copyright (C) 2021 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.117574");
  script_version("2021-07-23T06:15:26+0000");
  script_tag(name:"last_modification", value:"2021-07-23 10:28:28 +0000 (Fri, 23 Jul 2021)");
  script_tag(name:"creation_date", value:"2021-07-22 12:59:06 +0000 (Thu, 22 Jul 2021)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("Generic HTTP Directory Traversal (HTTP Web Dirs Check)");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "no404.nasl", "webmirror.nasl", "DDI_Directory_Scanner.nasl", "os_detection.nasl", "global_settings.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/disable_generic_webapp_scanning");

  script_xref(name:"URL", value:"https://owasp.org/www-community/attacks/Path_Traversal");

  script_tag(name:"summary", value:"Generic check for HTTP directory traversal vulnerabilities on
  each HTTP directory.

  NOTE: Please enable 'Enable generic web application scanning' within the VT 'Global variable
  settings' (OID: 1.3.6.1.4.1.25623.1.0.12288) if you want to run this script.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  access paths and directories that should normally not be accessible by a user. This can result in
  effects ranging from disclosure of confidential information to arbitrary code execution.");

  script_tag(name:"vuldetect", value:"Sends crafted HTTP requests to the each found directory of the
  remote web server and checks the response.");

  script_tag(name:"solution", value:"Contact the vendor for a solution.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"Mitigation");

  script_timeout(900);

  exit(0);
}

# nb: We also don't want to run if optimize_test is set to "no"
if( get_kb_item( "global_settings/disable_generic_webapp_scanning" ) )
  exit( 0 );

include("misc_func.inc");
include("host_details.inc");
include("os_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("port_service_func.inc");
include("list_array_func.inc");

# nb: "" was added here to catch the (normally quite unlikely) case that the file is accessible
# via e.g. http://example.com/foo/etc/passwd
traversals = traversal_pattern( extra_pattern_list:make_list( "" ) );
files = traversal_files();
count = 0;
max_count = 3;

port = http_get_port( default:80 );

# nb: No specific dir to test besides the ones found in the KB.
foreach dir( http_cgi_dirs( port:port ) ) {

  if( dir == "/" )
    continue; # nb: Already checked in 2017/gb_generic_http_web_root_dir_trav.nasl

  foreach traversal( traversals ) {
    foreach pattern( keys( files ) ) {
      file = files[pattern];
      url = dir + "/" + traversal + file;
      req = http_get( port:port, item:url );
      res = http_keepalive_send_recv( port:port, data:req );
      if( egrep( pattern:pattern, string:res, icase:TRUE ) ) {
        count++;
        vuln += http_report_vuln_url( port:port, url:url ) + '\n\n';
        vuln += 'Request:\n' + chomp( req ) + '\n\nResponse:\n' + chomp( res ) + '\n\n\n';
        if( count >= max_count )
          break; # nb: No need to continue with that much findings
      }
    }
    if( count >= max_count )
      break;
  }
  if( count >= max_count )
    break;
}

if( vuln ) {
  report = 'The following affected URL(s) were found (limited to ' + max_count + ' results):\n\n' + chomp( vuln );
  security_message( port:port, data:report );
}

exit( 0 );
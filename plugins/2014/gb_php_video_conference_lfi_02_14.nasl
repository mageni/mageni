###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_php_video_conference_lfi_02_14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# PHP Webcam Video Conference Local File Inclusion / XSS
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103902");
  script_version("$Revision: 11867 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("PHP Webcam Video Conference Local File Inclusion / XSS");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/31458/");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-02-07 11:53:08 +0100 (Fri, 07 Feb 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"impact", value:"A remote attacker can exploit this issue to obtain sensitive
information that could aid in further attacks.");
  script_tag(name:"vuldetect", value:"Send a HTTP GET request which tries to read a local file.");
  script_tag(name:"insight", value:"Input of the 's' value in rtmp_login.php is not properly sanitized.");
  script_tag(name:"solution", value:"Upgrade to the new version ifrom the videowhisper vendor homepage.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"PHP Webcam Video Conferenceis prone to a directory-traversal
vulnerability because it fails to sufficiently sanitize user-supplied input.");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default:80 );
if( ! can_host_php( port:port ) ) exit( 0 );

files = traversal_files();

foreach dir( make_list_unique( "/vc", "/vc_php", "/videoconference", cgi_dirs( port:port ) ) ) {

  if( dir == "/" ) dir = "";
  url = dir + '/index.php';
  res = http_get_cache( item:url, port:port );

  if( "<title>Video Conference by VideoWhisper.com" >< res ) {
    foreach file( keys( files ) ) {
      url = dir + '/rtmp_login.php?s=' + crap( data:"../", length:9*9 ) + files[file];
      if(http_vuln_check( port:port, url:url, pattern:file ) ) {
        report = report_vuln_url( port:port, url:url );
        security_message( port:port, data:report );
        exit( 0 );
      }
    }
  }
}

exit( 99 );

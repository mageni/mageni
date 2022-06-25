###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_apache_axis2_40327.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Apache Axis2 'engagingglobally' Cross-Site Scripting Vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.111005");
  script_version("$Revision: 11872 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-03-17 08:00:00 +0100 (Tue, 17 Mar 2015)");

  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_bugtraq_id(40327);
  script_cve_id("CVE-2010-2103");

  script_name("Apache Axis2 engagingglobally Cross-Site Scripting Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("gb_apache_axis2_detect.nasl");
  script_require_ports("Services/www", 8080, 8081);
  script_mandatory_keys("axis2/installed");

  script_tag(name:"solution", value:"The vendor has released fixes. Please see the references for more
 information.");
  script_tag(name:"summary", value:"Apache Axis2 is prone to a cross-site scripting vulnerability because
 it fails to properly sanitize user-supplied input.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code in
 the browser of an unsuspecting user in the context of the affected site. This may help the attacker steal
 cookie-based authentication credentials and to launch other attacks.");
  script_tag(name:"affected", value:"The issue affects versions prior to 1.5.2.");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40327");
  script_xref(name:"URL", value:"http://ws.apache.org/axis2/");
  script_xref(name:"URL", value:"http://www.exploit-db.com/exploits/12689");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version: vers, test_version: "1.5.2" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "1.5.2" + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

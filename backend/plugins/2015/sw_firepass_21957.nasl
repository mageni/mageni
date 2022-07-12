###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_firepass_21957.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# F5 Firepass Multiple Input Validation Vulnerabilities
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

CPE = 'cpe:/h:f5:firepass';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111016");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-17 08:00:00 +0100 (Fri, 17 Apr 2015)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_cve_id("CVE-2007-0195");
  script_bugtraq_id(21957);

  script_name("F5 Firepass Multiple Input Validation Vulnerabilities");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_firepass_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("firepass/installed");

  script_tag(name:"summary", value:"F5 Firepass is prone to multiple input-validation vulnerabilities.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The device fails to sufficiently sanitize user-supplied input.
  These issues include information-disclosure, security bypass, and cross-site scripting vulnerabilities.");
  script_tag(name:"impact", value:"An attacker can exploit these issues to bypass security restrictions,
  to view sensitive information, and to steal cookie-based authentication credentials. This may allow the
  attacker to compromise the application and the underlying system. Other attacks are also possible.");
  script_tag(name:"affected", value:"F5 Firepass from 5.4.0 to 5.5.1 and 6.0.0.");
  script_tag(name:"solution", value:"The vendor has released updates listened in the referred advisory.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/21957");
  script_xref(name:"URL", value:"https://support.f5.com/kb/en-us/solutions/public/6000/900/sol6923.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.4.0", test_version2:"5.5.1" )
    || version_is_equal( version:vers, test_version:"6.0.0" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "5.5.2/6.0.1" + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_sawmill_61075.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Sawmill < 8.6.3 Unspecified Remote Security Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2016 SCHUTZWERK GmbH, http://www.schutzwerk.com
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

CPE = "cpe:/a:sawmill:sawmill";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111083");
  script_version("$Revision: 11922 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-02-02 17:00:00 +0100 (Tue, 02 Feb 2016)");
  script_bugtraq_id(61075);
  script_cve_id("CVE-2013-4947");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Sawmill < 8.6.3 Unspecified Remote Security Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/61075");
  script_xref(name:"URL", value:"http://www.sawmill.net");
  script_xref(name:"URL", value:"http://www.sawmill.net/version_history8.html");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 SCHUTZWERK GmbH");
  script_dependencies("gb_sawmill_detect.nasl");
  script_require_ports("Services/www", 8988);
  script_require_keys("sawmill/installed");

  script_tag(name:"solution", value:"An update is available. Please see the references for details.");
  script_tag(name:"summary", value:"Sawmill is prone to an unspecified remote security vulnerability.");
  script_tag(name:"impact", value:"Little is known about this issue or its effects at this time.");
  script_tag(name:"affected", value:"Sawmill versions prior to 8.6.3 are vulnerable.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version: vers, test_version: "8.6.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"8.6.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

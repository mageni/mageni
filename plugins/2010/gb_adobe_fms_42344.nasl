###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_adobe_fms_42344.nasl 12653 2018-12-04 15:31:25Z cfischer $
#
# Adobe Flash Media Server Multiple Remote Security Vulnerabilities
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

CPE = "cpe:/a:adobe:flash_media_server";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100754");
  script_version("$Revision: 12653 $");
  script_tag(name:"last_modification", value:"$Date: 2018-12-04 16:31:25 +0100 (Tue, 04 Dec 2018) $");
  script_tag(name:"creation_date", value:"2010-08-11 13:11:12 +0200 (Wed, 11 Aug 2010)");
  script_bugtraq_id(42344);
  script_cve_id("CVE-2010-2218", "CVE-2010-2217", "CVE-2010-2219", "CVE-2010-2220");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("Adobe Flash Media Server Multiple Remote Security Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_adobe_fms_detect.nasl");
  script_require_ports("Services/www", 1111);
  script_mandatory_keys("Adobe/FMS/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/42344");
  script_xref(name:"URL", value:"http://www.adobe.com/products/flashmediaserver/");
  script_xref(name:"URL", value:"http://www.adobe.com/support/security/bulletins/apsb10-19.html");

  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code in the
  context of the affected application or cause denial-of-service conditions.");
  script_tag(name:"affected", value:"These issues affect Flash Media Server (FMS) versions prior to 3.5.4
  and 3.0.6.");
  script_tag(name:"solution", value:"Vendor updates are available. Please see the referenced advisory for
  more information.");
  script_tag(name:"summary", value:"Adobe Flash Media Server is prone to multiple remote security
  vulnerabilities, including multiple denial-of-service vulnerabilities
  and a remote code-execution vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"3.5", test_version2:"3.5.3" ) ||
    version_is_less( version:vers, test_version:"3.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.6/3.5.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
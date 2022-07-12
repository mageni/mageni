###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_40943.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# CUPS 'texttops' Filter NULL-pointer Dereference Vulnerability
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
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:apple:cups";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100685");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-21 20:36:15 +0200 (Mon, 21 Jun 2010)");
  script_bugtraq_id(40943);
  script_cve_id("CVE-2010-0542", "CVE-2010-2431", "CVE-2010-2432");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("CUPS 'texttops' Filter NULL-pointer Dereference Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40943");
  script_xref(name:"URL", value:"http://cups.org/articles.php?L596");
  script_xref(name:"URL", value:"http://www.cups.org");
  script_xref(name:"URL", value:"http://cups.org/str.php?L3516");

  script_tag(name:"impact", value:"Successful exploits may allow attackers to execute arbitrary code with
  the privileges of a user running the application. Failed exploit
  attempts likely cause denial-of-service conditions.");
  script_tag(name:"affected", value:"CUPS versions prior to 1.4.4 are affected.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"CUPS is prone to a NULL-pointer dereference vulnerability.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if( version_is_less( version:vers, test_version:"1.4.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
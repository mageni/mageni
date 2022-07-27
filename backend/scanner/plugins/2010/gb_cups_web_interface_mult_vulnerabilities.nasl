###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cups_web_interface_mult_vulnerabilities.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# CUPS Web Interface Multiple Vulnerabilities
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
  script_oid("1.3.6.1.4.1.25623.1.0.100687");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-06-22 12:10:21 +0200 (Tue, 22 Jun 2010)");
  script_bugtraq_id(40897, 40889);
  script_cve_id("CVE-2010-1748", "CVE-2010-0540");
  script_tag(name:"cvss_base", value:"6.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_name("CUPS Web Interface Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("secpod_cups_detect.nasl");
  script_require_ports("Services/www", 631);
  script_mandatory_keys("CUPS/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/40897");
  script_xref(name:"URL", value:"http://cups.org/articles.php?L596");
  script_xref(name:"URL", value:"http://www.apple.com/macosx/");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");
  script_tag(name:"summary", value:"CUPS Web Interface is prone to Multiple Vulnerabilities.

  1. A remote information-disclosure vulnerability. This
  issue affects the CUPS web interface component.

  Remote attackers can exploit this issue to obtain sensitive
  information that may lead to further attacks.

  2. A cross-site request-forgery vulnerability.

  Attackers can exploit this issue to perform certain administrative
  actions and gain unauthorized access to the affected application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( vers !~ "[0-9]+\.[0-9]+\.[0-9]+") exit( 0 ); # Version is not exact enough

if(version_is_less( version:vers, test_version:"1.4.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"1.4.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
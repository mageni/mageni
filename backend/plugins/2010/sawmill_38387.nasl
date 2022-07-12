###############################################################################
# OpenVAS Vulnerability Test
# $Id: sawmill_38387.nasl 13960 2019-03-01 13:18:27Z cfischer $
#
# Sawmill Unspecified Cross Site Scripting Vulnerability
#
# Authors:
# Michael Meyer
#
# Updated By: Antu Sanadi <santu@secpod.com> on 2010-03-29
# Updated the CVE
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

CPE = "cpe:/a:sawmill:sawmill";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100507");
  script_version("$Revision: 13960 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-01 14:18:27 +0100 (Fri, 01 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-02-24 18:35:31 +0100 (Wed, 24 Feb 2010)");
  script_bugtraq_id(38387);
  script_cve_id("CVE-2010-1079");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Sawmill Unspecified Cross Site Scripting Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/38387");
  script_xref(name:"URL", value:"http://www.sawmill.net");
  script_xref(name:"URL", value:"http://www.sawmill.net/version_history7.html");

  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_sawmill_detect.nasl");
  script_require_ports("Services/www", 8988);
  script_mandatory_keys("sawmill/installed");

  script_tag(name:"solution", value:"An update is available. Please see the references for details.");
  script_tag(name:"summary", value:"Sawmill is prone to a cross-site scripting vulnerability because it
 fails to properly sanitize user-supplied input.");
  script_tag(name:"impact", value:"An attacker may leverage this issue to execute arbitrary script code
 in the browser of an unsuspecting user in the context of the affected
 site. This may allow the attacker to steal cookie-based authentication
 credentials and to launch other attacks.");
  script_tag(name:"affected", value:"This issue affects versions prior to 7.2.18.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version: vers, test_version: "7.2.18" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"7.2.18" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

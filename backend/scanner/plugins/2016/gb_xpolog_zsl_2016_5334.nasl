###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xpolog_zsl_2016_5334.nasl 14181 2019-03-14 12:59:41Z cfischer $
#
# XpoLog Center V6 Multiple Remote Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:xpolog:xpolog_center";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105808");
  script_version("$Revision: 14181 $");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("XpoLog Center V6 Multiple Remote Vulnerabilities ");

  script_xref(name:"URL", value:"http://zeroscience.mk/en/vulnerabilities/ZSL-2016-5334.php");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Ask the vendor for an update.");
  script_tag(name:"summary", value:"XpoLog suffers from multiple vulnerabilities including XSS, Open Redirection and Cross-Site Request Forgery.");
  script_tag(name:"affected", value:"XpoLog <= 6.4469");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"last_modification", value:"$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $");
  script_tag(name:"creation_date", value:"2016-07-12 14:56:54 +0200 (Tue, 12 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_xpolog_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("xpolog_center/installed");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );

if( vers =  get_app_version( cpe:CPE, port:port ) )
{
  if( version_is_less_equal( version: vers, test_version: "6.4469" ) )
  {
    report = report_fixed_ver( installed_version:vers, fixed_version:'Ask vendor' );
    security_message( port:port, data:report );
    exit( 0 );
  }
}

exit( 99 );
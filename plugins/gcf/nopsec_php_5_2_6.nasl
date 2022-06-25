##############################################################################
# OpenVAS Vulnerability Test
# $Id: nopsec_php_5_2_6.nasl 10823 2018-08-07 18:08:40Z cfischer $
#
# PHP Version < 5.2.6 Multiple Vulnerabilities
#
# Authors:
# Songhan Yu <syu@nopsec.com>
#
# Copyright:
# Copyright NopSec Inc. 2012, http://www.nopsec.com
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

CPE = "cpe:/a:php:php";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.110183");
  script_version("$Revision: 10823 $");
  script_tag(name:"last_modification", value:"$Date: 2018-08-07 20:08:40 +0200 (Tue, 07 Aug 2018) $");
  script_tag(name:"creation_date", value:"2012-06-21 11:43:12 +0100 (Thu, 21 Jun 2012)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2007-4850", "CVE-2007-6039", "CVE-2008-0599",
                "CVE-2008-1384", "CVE-2008-2050", "CVE-2008-2051");
  script_bugtraq_id(27413, 28392, 29009);
  script_name("PHP Version < 5.2.6 Multiple Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright NopSec Inc. 2012");
  script_dependencies("gb_php_detect.nasl");
  script_mandatory_keys("php/installed");

  script_tag(name:"solution", value:"Update PHP to version 5.2.6 or later.");

  script_tag(name:"summary", value:"PHP version smaller than 5.2.6 suffers from multiple vulnerabilities.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( isnull( port = get_app_port( cpe:CPE ) ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"5.2.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.6" );
  security_message( data:report, port:port );
  exit( 0 );
}

exit( 99 );

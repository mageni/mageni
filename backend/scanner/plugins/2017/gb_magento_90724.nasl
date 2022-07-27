###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_magento_90724.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Magento < 2.0.6 Remote Code Execution Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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

CPE = 'cpe:/a:magentocommerce:magento';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108061");
  script_version("$Revision: 11874 $");
  script_bugtraq_id(90724);
  script_cve_id("CVE-2016-4010");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-30 11:00:00 +0100 (Mon, 30 Jan 2017)");
  script_name("Magento < 2.0.6 Remote Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magento/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/90724");
  script_xref(name:"URL", value:"http://netanelrub.in/2016/05/17/magento-unauthenticated-remote-code-execution/");

  script_tag(name:"summary", value:"The host is installed with Magento Web
  E-Commerce Platform and is prone to a remote code execution vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploiting this issue may allow an attacker to
  execute arbitrary code in the context of the affected application. Failed exploit attempts
  may cause a denial-of-service condition.");

  script_tag(name:"affected", value:"Magento CE and EE before 2.0.6.");

  script_tag(name:"solution", value:"Update to Magento CE or EE 2.0.6 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  script_xref(name:"URL", value:"https://www.magentocommerce.com/products/downloads/magento");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.0.6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.0.6" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

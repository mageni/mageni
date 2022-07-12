###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_magento_56453.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Magento SSL Certificate Validation Security Bypass Vulnerability
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

CPE = 'cpe:/a:magentocommerce:magento';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105226");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-02-23 12:00:00 +0100 (Mon, 23 Feb 2015)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_bugtraq_id(56453);
  script_cve_id("CVE-2011-5240");
  script_name("Magento SSL Certificate Validation Security Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_magento_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("magento/installed");

  script_tag(name:"summary", value:"This web application is running with the Vaadin Framework which
  is prone to a security-bypass vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"Magento is prone to a security-bypass vulnerability because the
  application fails to properly validate SSL certificates from a server.");
  script_tag(name:"impact", value:"Successfully exploiting this issue allows attackers to perform
  man-in-the-middle attacks or impersonate trusted servers, which will aid further attacks.");
  script_tag(name:"affected", value:"Magento 1.5 and 1.6.2 are vulnerable.");
  script_tag(name:"solution", value:"Check for updated versions of Magento");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/56453");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"1.5", test_version2:"1.6.2" ) ) {
  security_message( port:port );
  exit( 0 );
}

exit( 99 );

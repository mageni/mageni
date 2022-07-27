##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_csrf_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# HP System Management Homepage Cross-site Request Forgery Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:system_management_homepage";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802758");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2011-3846");
  script_bugtraq_id(52974);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-23 13:36:33 +0530 (Mon, 23 Apr 2012)");
  script_name("HP System Management Homepage Cross-site Request Forgery Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_xref(name:"URL", value:"http://secunia.com/advisories/43012");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52974");

  script_tag(name:"insight", value:"The flaw is due to certain actions via HTTP requests without
  performing any validity checks to verify the requests.");
  script_tag(name:"solution", value:"Upgrade to HP System Management Homepage (SMH) version 7.0 or later.");
  script_tag(name:"summary", value:"This host is running HP System Management Homepage (SMH) and is
  prone to cross-site request forgery vulnerability.");
  script_tag(name:"impact", value:"Successful exploitation will allow remote attackers to create an arbitrary
  user with administrative privileges, if a logged-in administrative user visits
  a malicious web site.");
  script_tag(name:"affected", value:"HP System Management Homepage (SMH) version 6.2.2.7");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://h18000.www1.hp.com/products/servers/management/agents/index.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_equal( version:version, test_version:"6.2.2.7" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
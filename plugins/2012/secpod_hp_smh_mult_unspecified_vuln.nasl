##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_hp_smh_mult_unspecified_vuln.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# HP System Management Homepage Multiple Unspecified Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 SecPod, http://www.secpod.com
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
  script_oid("1.3.6.1.4.1.25623.1.0.903020");
  script_version("$Revision: 11857 $");
  script_cve_id("CVE-2012-1993", "CVE-2012-0135");
  script_bugtraq_id(53121);
  script_tag(name:"cvss_base", value:"3.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-04-25 13:28:29 +0530 (Wed, 25 Apr 2012)");
  script_name("HP System Management Homepage Multiple Unspecified Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2012 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_xref(name:"URL", value:"http://secunia.com/advisories/43012/");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1026925");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/522374");
  script_xref(name:"URL", value:"http://h18000.www1.hp.com/products/servers/management/agents/index.html");

  script_tag(name:"insight", value:"The flaws are due to multiple unspecified errors, which allows
  attackers to gain sensitive information or cause denial of service via
  unknown vectors.");
  script_tag(name:"solution", value:"Upgrade to HP System Management Homepage (SMH) version 7.0 or later.");
  script_tag(name:"summary", value:"This host is running HP System Management Homepage (SMH) and is
  prone to multiple unspecified vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to to gain sensitive information
  or cause denial of service condition.");
  script_tag(name:"affected", value:"HP System Management Homepage (SMH) version prior to 7.0");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:"7.0" ) ){
  report = report_fixed_ver( installed_version:version, fixed_version:"7.0");
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
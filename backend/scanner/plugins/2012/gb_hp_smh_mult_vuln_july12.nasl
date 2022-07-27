##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_smh_mult_vuln_july12.nasl 11857 2018-10-12 08:25:16Z cfischer $
#
# HP System Management Homepage Multiple Vulnerabilities - Jul12
#
# Authors:
# Sooraj KS <kssooraj@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.802657");
  script_version("$Revision: 11857 $");
  script_bugtraq_id(54218);
  script_cve_id("CVE-2012-2012", "CVE-2012-2013", "CVE-2012-2014", "CVE-2012-2015",
                "CVE-2012-2016");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2012-07-09 15:15:15 +0530 (Mon, 09 Jul 2012)");
  script_name("HP System Management Homepage Multiple Vulnerabilities - Jul12");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_smh_detect.nasl");
  script_mandatory_keys("HP/SMH/installed");
  script_require_ports("Services/www", 2301, 2381);

  script_xref(name:"URL", value:"http://secunia.com/advisories/49592");
  script_xref(name:"URL", value:"http://securitytracker.com/id/1027209");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/54218");
  script_xref(name:"URL", value:"http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03360041");

  script_tag(name:"insight", value:"- An unspecified local security vulnerability

  - A denial of service vulnerability

  - An input validation vulnerability

  - A privilege escalation vulnerability

  - An information-disclosure vulnerability");
  script_tag(name:"solution", value:"Upgrade to HP System Management Homepage (SMH) version 7.1.1 or later.");
  script_tag(name:"summary", value:"This host is running HP System Management Homepage (SMH) and is
  prone to multiple vulnerabilities.");
  script_tag(name:"impact", value:"Successful exploitation will allow attackers to gain elevated privileges,
  disclose sensitive information, perform unauthorized actions, or cause
  denial of service conditions.");
  script_tag(name:"affected", value:"HP System Management Homepage (SMH) versions before 7.1.1");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  script_xref(name:"URL", value:"http://h18013.www1.hp.com/products/servers/management/agents/documentation.html");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! version = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:version, test_version:"7.1.1" ) ) {
  report = report_fixed_ver( installed_version:version, fixed_version:"7.1.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
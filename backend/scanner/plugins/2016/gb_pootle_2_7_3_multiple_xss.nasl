###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_pootle_2_7_3_multiple_xss.nasl 11961 2018-10-18 10:49:40Z asteins $
#
# Pootle Server < 2.7.3 Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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

CPE = "cpe:/a:translatehouse:pootle";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108009");
  script_version("$Revision: 11961 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-18 12:49:40 +0200 (Thu, 18 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-26 14:47:00 +0200 (Wed, 26 Oct 2016)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_name("Pootle Server < 2.7.3 Multiple Cross Site Scripting Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_pootle_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("pootle_server/installed");

  script_xref(name:"URL", value:"https://github.com/translate/pootle/releases/tag/2.7.3");

  script_tag(name:"summary", value:"This host is running a Pootle server which is prone
  to multiple cross site scripting vulnerabilities.");

  script_tag(name:"impact", value:"Successful exploitation will allow remote
  attacker to execute arbitrary javascript code in the context of the current user.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"affected", value:"All systems running Pootle Server versions prior to 2.7.3.");

  script_tag(name:"solution", value:"Update your Pootle Server to a not vulnerable version 2.7.3 and later");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.7.3" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.7.3" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

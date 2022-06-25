###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kunena_forum_xss_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Kunena Forum Extension 'message subject' Cross Site Scripting Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:kunena:kunena";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108106");
  script_version("$Revision: 11863 $");
  script_cve_id("CVE-2017-5673");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-23 09:57:33 +0100 (Thu, 23 Mar 2017)");
  script_name("Kunena Forum Extension 'message subject' Cross Site Scripting Vulnerability");
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_dependencies("gb_kunena_forum_detect.nasl");
  script_mandatory_keys("kunena_forum/installed");
  script_require_ports("Services/www", 80);

  script_xref(name:"URL", value:"http://www.fox.ra.it/technical-articles/kunena-vulnerability-2017-01.html");

  script_tag(name:"summary", value:"This host is installed with the Kunena Forum Extension for Joomla
  and is prone to a cross-site scripting vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successfully exploitation will allow remote
  attacker to execute arbitrary script code in the browser of an unsuspecting user
  in the context of the affected site. This may allow the attacker to steal
  cookie-based authentication credentials and to launch other attacks.");

  script_tag(name:"affected", value:"Kunena Forum Extension versions 5.0.2 through 5.0.4.");

  script_tag(name:"solution", value:"Update the Kunena Forum Extension to version 5.0.5 or higher.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_in_range( version:vers, test_version:"5.0.2", test_version2:"5.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.0.5" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

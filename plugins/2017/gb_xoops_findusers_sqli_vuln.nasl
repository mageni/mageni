##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xoops_findusers_sqli_vuln.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# XOOPS 'findusers.php' SQL Injection Vulnerability
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

CPE = "cpe:/a:xoops:xoops";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108137");
  script_version("$Revision: 11863 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-04-13 12:06:51 +0200 (Thu, 13 Apr 2017)");
  script_cve_id("CVE-2017-7290");
  script_bugtraq_id(97230);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_name("XOOPS 'findusers.php' SQL Injection Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_xoops_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("XOOPS/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/97230");
  script_xref(name:"URL", value:"https://gist.github.com/jk1986/3b304ac6b4ae52ae667bba380c2dce19");

  script_tag(name:"summary", value:"This host is running XOOPS and is prone to a sql injection vulnerability.");
  script_tag(name:"insight", value:"The flaw exists due to XOOPS allowing remote authenticated administrators to execute
  arbitrary SQL commands via the url parameter to findusers.php. An example attack uses 'into outfile'
  to create a backdoor program.");
  script_tag(name:"impact", value:"Exploiting this issue could allow an attacker to compromise the application, access or
  modify data, or exploit latent vulnerabilities in the underlying database.");
  script_tag(name:"affected", value:"XOOPS version prior to 2.5.8.1");
  script_tag(name:"solution", value:"Upgrade to XOOPS version 2.5.8.1 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");


  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"2.5.8.1" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.5.8.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

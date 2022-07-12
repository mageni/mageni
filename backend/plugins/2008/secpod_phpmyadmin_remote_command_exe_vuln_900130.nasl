##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_phpmyadmin_remote_command_exe_vuln_900130.nasl 14010 2019-03-06 08:24:33Z cfischer $
#
# phpMyAdmin 'server_databases.php' Remote Command Execution Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

CPE = "cpe:/a:phpmyadmin:phpmyadmin";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900130");
  script_version("$Revision: 14010 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $");
  script_tag(name:"creation_date", value:"2008-10-03 15:12:54 +0200 (Fri, 03 Oct 2008)");
  script_cve_id("CVE-2008-4096");
  script_bugtraq_id(31188);
  script_copyright("Copyright (C) 2008 SecPod");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_name("phpMyAdmin 'server_databases.php' Remote Command Execution Vulnerability");
  script_dependencies("secpod_phpmyadmin_detect_900129.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpMyAdmin/installed");

  script_xref(name:"URL", value:"http://comments.gmane.org/gmane.comp.security.oss.general/947?set_lines=100000");
  script_xref(name:"URL", value:"http://fd.the-wildcat.de/pma_e36a091q11.php");
  script_xref(name:"URL", value:"http://www.phpmyadmin.net/home_page/security.php?issue=PMASA-2008-7");
  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/31188/exploit");

  script_tag(name:"summary", value:"phpMyAdmin is prone to Remote Command Execution vulnerability.");

  script_tag(name:"insight", value:"This issue is caused by, sort_by parameter in server_databases.php
  which is not properly sanitised before being used.");

  script_tag(name:"affected", value:"phpMyAdmin versions prior to 2.11.9.1.");

  script_tag(name:"solution", value:"Upgrade to phpMyAdmin 2.11.9.1 or later.");

  script_tag(name:"impact", value:"Successful exploitation allows execution of arbitrary
  commands, and possibly compromise the affected application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( egrep( pattern:"^([01]\..*|2\.(([0-9]|10)(\..*)|11\.([0-8](\..*)?|9\.0)))", string:vers ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"2.11.9.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
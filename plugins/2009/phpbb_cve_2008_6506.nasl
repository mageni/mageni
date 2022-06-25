###############################################################################
# OpenVAS Vulnerability Test
# $Id: phpbb_cve_2008_6506.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# phpBB Account Re-Activation Authentication Bypass Vulnerability
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:phpbb:phpbb";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100086");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-03-29 17:14:47 +0200 (Sun, 29 Mar 2009)");
  script_bugtraq_id(32842);
  script_cve_id("CVE-2008-6506");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_name("phpBB Account Re-Activation Authentication Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("phpbb_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("phpBB/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/32842");
  script_xref(name:"URL", value:"http://www.phpbb.com/");

  script_tag(name:"impact", value:"Attackers can exploit this vulnerability to gain unauthorized access
  to the affected application, which may aid in further attacks.");

  script_tag(name:"affected", value:"Versions prior to phpBB 3.0.4 are vulnerable.");

  script_tag(name:"solution", value:"Update to version 3.0.4 or later.");

  script_tag(name:"summary", value:"According to its version number, the remote version of phpbb
  is prone to an authentication-bypass vulnerability because it fails
  to properly enforce privilege requirements on some operations.");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_is_less( version:vers, test_version:"3.0.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"3.0.4" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
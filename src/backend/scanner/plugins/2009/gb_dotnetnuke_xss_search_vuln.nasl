##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_dotnetnuke_xss_search_vuln.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# DotNetNuke Cross Site Scripting Vulnerability
#
# Authors:
# Veerendra GG <veernedragg@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:dotnetnuke:dotnetnuke";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.800152");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-12-02 13:54:57 +0100 (Wed, 02 Dec 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2009-4110");
  script_bugtraq_id(37139);
  script_name("DotNetNuke Cross Site Scripting Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_dotnetnuke_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("dotnetnuke/installed");

  script_tag(name:"impact", value:"Successful attack could lead to execution of arbitrary HTML and script code
  in the context of an affected site.");

  script_tag(name:"affected", value:"DotNetNuke versions 4.8 through 5.1.4 on all running platforms.");

  script_tag(name:"insight", value:"The flaw is due to input passed to the search parameters are not properly
  sanitized before being returned to the user.");

  script_tag(name:"solution", value:"Update to version 5.2.0 or later.");

  script_tag(name:"summary", value:"The host is installed with DotNetNuke and is prone to Cross Site
  Scripting Vulnerability.");

  script_xref(name:"URL", value:"http://secunia.com/advisories/37480");
  script_xref(name:"URL", value:"http://www.dotnetnuke.com/News/SecurityPolicy/securitybulletinno31/tabid/1450/Default.aspx");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if( version_in_range( version:vers, test_version:"4.8", test_version2:"5.1.4" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"5.2.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
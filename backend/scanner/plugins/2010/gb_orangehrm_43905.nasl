###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_orangehrm_43905.nasl 11249 2018-09-05 13:55:42Z cfischer $
#
# OrangeHRM 'uri' Parameter Local File Include Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH
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

CPE = "cpe:/a:orangehrm:orangehrm";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100851");
  script_version("$Revision: 11249 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-05 15:55:42 +0200 (Wed, 05 Sep 2018) $");
  script_tag(name:"creation_date", value:"2010-10-12 12:50:34 +0200 (Tue, 12 Oct 2010)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cve_id("CVE-2010-4798");
  script_bugtraq_id(43905);
  script_name("OrangeHRM 'uri' Parameter Local File Include Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_orangehrm_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("orangehrm/detected");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/43905");
  script_xref(name:"URL", value:"http://sourceforge.net/projects/orangehrm/");

  script_tag(name:"summary", value:"OrangeHRM is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input.");

  script_tag(name:"impact", value:"An attacker can exploit this vulnerability to obtain potentially
  sensitive information or to execute arbitrary local scripts in the context of the webserver process.
  This may allow the attacker to compromise the application and the computer. Other attacks are
  also possible.");

  script_tag(name:"affected", value:"OrangeHRM 2.6.0.1 is vulnerable. Other versions may also be affected.");

  script_tag(name:"solution", value:"No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one.");

  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! infos = get_app_version_and_location( cpe:CPE, port:port, exit_no_version:TRUE ) ) exit( 0 );
ver = infos['version'];
dir = infos['location'];

if( version_is_equal( version:ver, test_version:"2.6.1" ) ) {
  report = report_fixed_ver( installed_version:ver, fixed_version:"WillNotFix", install_path:dir );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
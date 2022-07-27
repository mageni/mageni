###################################################################
# OpenVAS Vulnerability Test
# $Id: openca_html_injection.nasl 14031 2019-03-07 10:47:29Z cfischer $
#
# OpenCA HTML injection
#
# LSS-NVT-2009-007
#
# Developed by LSS Security Team <http://security.lss.hr>
#
# Copyright (C) 2009 LSS <http://www.lss.hr>
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
# You should have received a copy of the GNU General Public
# License along with this program. If not, see
# <http://www.gnu.org/licenses/>.
###################################################################

CPE = "cpe:/a:openca:openca";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.102007");
  script_version("$Revision: 14031 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2009-07-28 17:03:43 +0200 (Tue, 28 Jul 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_cve_id("CVE-2004-0787");
  script_bugtraq_id(11113);
  script_name("OpenCA HTML injection");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("Copyright (C) 2009 LSS");
  script_dependencies("gb_openca_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("openca/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/11113");

  script_tag(name:"solution", value:"Upgrade OpenCA to the newer version.");

  script_tag(name:"summary", value:"OpenCA is vulnerable to a HTML injection attack due to inadequate
  validation / filtering of user input into a web form frontend.");

  script_tag(name:"affected", value:"Versions up to 0.9.2 RC6 are vulnerable.");

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

if( version_is_less_equal( version:vers, test_version:"0.9.2-rc6" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"0.9.2" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
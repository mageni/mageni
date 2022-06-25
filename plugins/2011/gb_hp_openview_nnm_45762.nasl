###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_45762.nasl 11997 2018-10-20 11:59:41Z mmartin $
#
# HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
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

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103026");
  script_version("$Revision: 11997 $");
  script_bugtraq_id(45762);
  script_cve_id("CVE-2011-0261", "CVE-2011-0262", "CVE-2011-0263", "CVE-2011-0264", "CVE-2011-0265", "CVE-2011-0266", "CVE-2011-0267", "CVE-2011-0268", "CVE-2011-0269", "CVE-2011-0270", "CVE-2011-0271");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2018-10-20 13:59:41 +0200 (Sat, 20 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-01-13 13:28:59 +0100 (Thu, 13 Jan 2011)");
  script_name("HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_require_ports("Services/www", 7510);
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"https://www.securityfocus.com/bid/45762");
  script_xref(name:"URL", value:"http://openview.hp.com/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/515628");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-003/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-004/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-005/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-006/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-007/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-008/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-009/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-010/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-011/");
  script_xref(name:"URL", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-012/");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager is prone to multiple remote code-
  execution vulnerabilities.");
  script_tag(name:"affected", value:"OpenView Network Node Manager 7.51 and 7.53 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available. Please see the references for details.");
  script_tag(name:"impact", value:"Successful exploits may allow an attacker to execute arbitrary code
  with the privileges of the user running the application's webserver. Failed exploit
  attempts will likely result in denial-of-service conditions.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
get_app_version( cpe:CPE, port:port );
if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) ) exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_50471.nasl 12018 2018-10-22 13:31:29Z mmartin $
#
# HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.103364");
  script_bugtraq_id(50471);
  script_cve_id("CVE-2011-3166", "CVE-2011-3167");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12018 $");
  script_name("HP OpenView Network Node Manager Multiple Remote Code Execution Vulnerabilities");
  script_tag(name:"last_modification", value:"$Date: 2018-10-22 15:31:29 +0200 (Mon, 22 Oct 2018) $");
  script_tag(name:"creation_date", value:"2011-12-14 09:14:18 +0100 (Wed, 14 Dec 2011)");
  script_category(ACT_GATHER_INFO);
  script_family("Web application abuses");
  script_copyright("This script is Copyright (C) 2011 Greenbone Networks GmbH");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_require_ports("Services/www", 7510);
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/50471");
  script_xref(name:"URL", value:"http://www.openview.hp.com/products/nnm/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/520349");

  script_tag(name:"summary", value:"HP OpenView Network Node Manager (NNM) is prone to multiple remote
  code-execution vulnerabilities because it fails to sanitize user-supplied data.");
  script_tag(name:"affected", value:"These issues affects NNM 7.51, v7.53 running on HP-UX, Linux, Solaris,
  and Windows. Other versions and platforms may also be affected.");
  script_tag(name:"solution", value:"Updates are available.Please contact the vendor for more information.");
  script_tag(name:"impact", value:"An attacker can exploit these issues to execute arbitrary code with
  the privileges of the user running the affected application.
  Successful exploits will compromise the affected application and
  possibly the underlying computer.");

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

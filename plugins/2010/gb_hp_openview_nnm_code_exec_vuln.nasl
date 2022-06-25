###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_openview_nnm_code_exec_vuln.nasl 14037 2019-03-07 11:35:56Z cfischer $
#
# HP OpenView Network Node Manager Code Execution Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

CPE = "cpe:/a:hp:openview_network_node_manager";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801389");
  script_version("$Revision: 14037 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-07 12:35:56 +0100 (Thu, 07 Mar 2019) $");
  script_tag(name:"creation_date", value:"2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)");
  script_bugtraq_id(34812);
  script_cve_id("CVE-2009-0720");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_name("HP OpenView Network Node Manager Code Execution Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("secpod_hp_openview_nnm_detect.nasl");
  script_require_ports("Services/www", 7510);
  script_mandatory_keys("HP/OVNNM/installed");

  script_xref(name:"URL", value:"http://marc.info/?l=bugtraq&m=124146030732511&w=2");
  script_xref(name:"URL", value:"http://securitytracker.com/alerts/2009/May/1022163.html");
  script_xref(name:"URL", value:"http://support.openview.hp.com/selfsolve/patches");

  script_tag(name:"summary", value:"This host is running HP OpenView Network Node Manager and
  is prone to code execution vulnerabilities.");

  script_tag(name:"insight", value:"The flaw is due to an unspecified error when processing specially crafted
  data, which could allow remote attackers to crash an affected process or execute arbitrary code via a malicious request.");

  script_tag(name:"affected", value:"HP OpenView Network Node Manager versions 7.01, 7.51 and 7.53.");

  script_tag(name:"solution", value:"Apply the update from the referenced advisory.");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to execute arbitrary code in
  the context of an application.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) )
  exit( 0 );

if(!get_app_version( cpe:CPE, port:port ))
  exit( 0 );

if( ! vers = get_kb_item( "www/"+ port + "/HP/OVNNM/Ver" ) )
  exit( 0 );

if( version_is_equal( version:vers, test_version:"B.07.51" ) ||
    version_is_equal( version:vers, test_version:"B.07.53" ) ||
    version_is_equal( version:vers, test_version:"B.07.01" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"See references" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
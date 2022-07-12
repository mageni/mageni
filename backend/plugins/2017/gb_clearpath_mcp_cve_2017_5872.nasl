###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_clearpath_mcp_cve_2017_5872.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Unisys ClearPath MCP Denial of Service Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:unisys:clearpath_mcp";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140189");
  script_bugtraq_id(96782);
  script_cve_id("CVE-2017-5872");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 12106 $");

  script_name("Unisys ClearPath MCP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/96782");
  script_xref(name:"URL", value:"http://www.unisys.com");
  script_xref(name:"URL", value:"https://public.support.unisys.com/common/public/vulnerability/NVD_Detail_Rpt.aspx?ID=42");
  script_tag(name:"impact", value:"Attackers can exploit this issue to cause a denial-of-service condition.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Updates are available. Please see the references or vendor advisory for more information.");
  script_tag(name:"summary", value:"Unisys ClearPath MCP is prone to a denial-of-service vulnerability.");
  script_tag(name:"affected", value:"ClearPath MCP system running 57.1 (before 57.152) or 58.1 (before 58.142) Networking and at least one service offering secured connections via SSL/TLS.");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable"); # and at least one service offering secured connections via SSL/TLS.

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-03-14 18:08:09 +0100 (Tue, 14 Mar 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_clearpath_mcp_ftp_detect.nasl");
  script_mandatory_keys("unisys/clearpath_mcp/version");
  script_require_ports("Services/ftp", 21);

  exit(0);
}


include("version_func.inc");
include("host_details.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ '^57\\.' )
  fix = '57.152';
else if( version =~ '^58\\.' )
  fix = '58.142';
else
  exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( data:report, port:0 );
  exit( 0 );
}

exit( 99 );


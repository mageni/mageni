###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_manageengine_servicedesk_plus_93215.nasl 11919 2018-10-16 09:49:19Z mmartin $
#
# ManageEngine ServiceDesk Plus < 9.0 Access Bypass Vulnerability
#
# Authors:
# Christian Fischer <christian.fischer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
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

CPE = "cpe:/a:manageengine:servicedesk_plus";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108158");
  script_version("$Revision: 11919 $");
  script_cve_id("CVE-2016-4889");
  script_bugtraq_id(93215);
  script_tag(name:"cvss_base", value:"6.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-10-16 11:49:19 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-05-12 09:37:58 +0200 (Fri, 12 May 2017)");
  script_name("ManageEngine ServiceDesk Plus < 9.0 Access Bypass Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2017 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_ManageEngine_ServiceDesk_Plus_detect.nasl");
  script_require_ports("Services/www", 8080);
  script_mandatory_keys("ManageEngine/ServiceDeskPlus/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/93215");
  script_xref(name:"URL", value:"https://www.manageengine.com/products/service-desk/readme-9.0.html");

  script_tag(name:"summary", value:"This host is installed with ManageEngine ServiceDesk Plus and
  is prone to a access bypass vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"impact", value:"Successful exploitation will allow a remote authenticated guest user
  to have unspecified impact by leveraging failure to restrict access to unknown functions.");

  script_tag(name:"affected", value:"ManageEngine ServiceDesk Plus version prior to 9.0.");

  script_tag(name:"solution", value:"Upgrade to ManageEngine ServiceDesk Plus 9.0 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

version = str_replace( string:vers, find:"build", replace:"." );

if( version_is_less( version:version, test_version:"9.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"9.0" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
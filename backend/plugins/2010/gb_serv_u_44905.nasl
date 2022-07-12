###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serv_u_44905.nasl 13564 2019-02-11 07:54:43Z cfischer $
#
# Serv-U Empty Password Authentication Bypass Vulnerability
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

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100914");
  script_version("$Revision: 13564 $");
  script_tag(name:"last_modification", value:"$Date: 2019-02-11 08:54:43 +0100 (Mon, 11 Feb 2019) $");
  script_tag(name:"creation_date", value:"2010-11-25 12:46:25 +0100 (Thu, 25 Nov 2010)");
  script_bugtraq_id(44905);
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_name("Serv-U Empty Password Authentication Bypass Vulnerability");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/44905");
  script_xref(name:"URL", value:"http://www.serv-u.com/");
  script_xref(name:"URL", value:"http://www.serv-u.com/releasenotes/");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2010 Greenbone Networks GmbH");
  script_dependencies("gb_rhinosoft_serv-u_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("Serv-U/SSH/detected");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"solution", value:"Updates are available. Please see the references for more information.");

  script_tag(name:"summary", value:"Serv-U is prone to an authentication-bypass vulnerability.");

  script_tag(name:"impact", value:"Attackers can exploit this issue to gain unauthorized access to the
  affected application. However, this requires that the application has password-based authentication disabled.");

  script_tag(name:"affected", value:"Serv-U 10.2.0.2 and versions prior to 10.3.0.1 are vulnerable.");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE, service:"ssh" ) )
  exit( 0 );

if( ! vers = get_app_version( cpe:CPE, port:port ) )
  exit( 0 );

if(version_in_range( version:vers, test_version:"10.2.0.2", test_version2:"10.3.0.0" ) ) {
  report = report_fixed_ver( installed_version:vers, fixed_version:"10.3.0.1" );
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );
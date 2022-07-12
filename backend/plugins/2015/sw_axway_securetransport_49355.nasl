###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_axway_securetransport_49355.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Axway SecureTransport Directory Traversal Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

CPE = 'cpe:/a:axway:securetransport';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111021");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-04-22 08:00:00 +0200 (Wed, 22 Apr 2015)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_bugtraq_id(49355);

  script_name("Axway SecureTransport Directory Traversal Vulnerability");

  script_category(ACT_GATHER_INFO);
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_family("Web application abuses");
  script_dependencies("sw_axway_securetransport_detect.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("axway_securetransport/installed");

  script_tag(name:"summary", value:"Axway SecureTransport is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input data.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"impact", value:"Exploiting the issue may allow an attacker to obtain sensitive information
  that could aid in further attacks.");
  script_tag(name:"affected", value:"SecureTransport 4.8.x prior to 4.8.2 Patch 12 are vulnerable.");
  script_tag(name:"solution", value:"The vendor has released updates.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/49355");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/519464");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if( version_is_less( version:vers, test_version:"4.8.2" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "4.8.2 Patch 12" + '\n';
  security_message( port:port, data:report );
  exit( 0 );
}

exit( 99 );

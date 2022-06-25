###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_dropbear_ssh_52159.nasl 12095 2018-10-25 12:00:24Z cfischer $
#
# Dropbear SSH Server Use-after-free Vulnerability
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2014 SCHUTZWERK GmbH
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

CPE = 'cpe:/a:matt_johnston:dropbear_ssh_server';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105113");
  script_version("$Revision: 12095 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:00:24 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-11-07 12:40:00 +0100 (Fri, 07 Nov 2014)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:S/C:C/I:C/A:C");

  script_cve_id("CVE-2012-0920");
  script_bugtraq_id(52159);

  script_name("Dropbear SSH Server Use-after-free Vulnerability");


  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (c) 2014 SCHUTZWERK GmbH");
  script_family("General");
  script_dependencies("gb_dropbear_ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);
  script_mandatory_keys("dropbear/installed");

  script_tag(name:"summary", value:"This host is installed with Dropbear SSH Server and
  is prone to a use-after-free vulnerability.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"A use-after-free vulnerability exists in Dropbear SSH
  Server 0.52 through 2011.54 when command restriction and public key authentication are enabled.");
  script_tag(name:"impact", value:"This flaw allows remote authenticated users
  to execute arbitrary code and bypass command restrictions via multiple crafted
  command requests, related to channels concurrency.");
  script_tag(name:"affected", value:"Versions of Dropbear SSH Server 0.52 through
  2011.54 are vulnerable.");
  script_tag(name:"solution", value:"Updates are available.");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/52159");
  script_xref(name:"URL", value:"https://matt.ucc.asn.au/dropbear/dropbear.html");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! vers = get_app_version( cpe:CPE, port:port ) ) exit( 0 );

ver = eregmatch( pattern:"^([0-9]+)\.([0-9]+)", string:vers );

if( isnull( ver[2] ) ) exit( 0 );

if( int( ver[1] ) > 2011 ) exit( 99 );

if( version_in_range( version:ver[2], test_version:"52", test_version2:"54" ) ) {

  report = 'Installed version: ' + vers + '\n' +
           'Fixed version:     ' + "2012.55" + '\n';
  security_message( port:port, data:report );
  exit (0 );
}

exit( 99 );

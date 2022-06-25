###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2015_0005.nasl 12131 2018-10-26 14:03:52Z mmartin $
#
# Palo Alto PAN-OS PAN-SA-2015-0005
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
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

CPE = 'cpe:/o:paloaltonetworks:pan-os';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105325");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12131 $");

  script_name("Palo Alto PAN-OS PAN-SA-2015-0005");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/32");

  script_tag(name:"summary", value:"Devices running PAN-OS 7.0.0 (including Panorama) that are configured to use LDAP for captive portal or device management authentication
do not properly perform authentication against the LDAP server in specific cases, leading to an authentication bypass. There is no issue if you are using Radius or local
authentication instead of LDAP or prior versions of PAN-OS. This does not affect authentication attempts from GlobalProtect clients either.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 7.0.1");

  script_tag(name:"impact", value:"This vulnerability can lead to authentication bypass for captive portal or device management login attempts.");

  script_tag(name:"affected", value:"PAN-OS 7.0.0");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 16:03:52 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-20 11:43:06 +0200 (Thu, 20 Aug 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Palo Alto PAN-OS Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("gb_palo_alto_panOS_version.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

model = get_kb_item( "palo_alto_pan_os/model" );

if( version == "7.0.0" ) fix = '7.0.1';

if( fix )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix;

  if( model )
    report += '\nModel:             ' + model;

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


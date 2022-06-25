###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2016_0008.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Palo Alto PAN-OS PAN-SA-2016-0008
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105793");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12096 $");

  script_name("Palo Alto PAN-OS PAN-SA-2016-0008");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/41");

  script_tag(name:"summary", value:"Palo Alto Networks firewalls offer an API to query and modify the configuration of the device. While access to this API is protected by the use of an API key, an issue was recently identified leading to a potential unauthenticated denial of service attack. (Ref #91728)");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 7.0.8 or later");

  script_tag(name:"impact", value:"The API is hosted on a dedicated management interface and, while this issue can result in a DoS attack of the API, it doesn't compromise the security functionality of the device.");

  script_tag(name:"affected", value:"PAN-OS 7.0.1 to PAN-OS 7.0.7");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-07-05 16:55:13 +0200 (Tue, 05 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Palo Alto PAN-OS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_palo_alto_panOS_version.nasl");
  script_mandatory_keys("palo_alto_pan_os/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

model = get_kb_item( "palo_alto_pan_os/model" );

if( version_in_range( version:version, test_version:"7.0.1", test_version2:"7.0.7" ) ) fix = '7.0.8';

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


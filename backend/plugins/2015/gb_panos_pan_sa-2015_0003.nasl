###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2015_0003.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# Palo Alto PAN-OS PAN-SA-2015-0003
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
  script_oid("1.3.6.1.4.1.25623.1.0.105281");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12106 $");

  script_name("Palo Alto PAN-OS PAN-SA-2015-0003");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/30");

  script_tag(name:"impact", value:"This issue affects the management interface of the device, where an authenticated administrator
may be tricked into injecting malicious javascript into the web UI interface.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 6.1.3, PAN-OS 6.0.9, or PAN-OS 5.0.16");

  script_tag(name:"summary", value:"A cross-site scripting vulnerability exists in the web-based device management interface whereby
data provided by the user is echoed back to the user without sanitization. (Ref# 73638)");

  script_tag(name:"affected", value:"PAN-OS 6.1.2 and earlier, PAN-OS 6.0.8 and earlier, PAN-OS 5.0.15 and earlier");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-05-27 14:38:26 +0200 (Wed, 27 May 2015)");
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

if( version_is_less_equal( version:version, test_version:"5.0.15" ) ) fix = '5.0.16';
else if( version_in_range( version:version, test_version:"6.0", test_version2:"6.0.8" ) ) fix = '6.0.9';
else if( version_in_range( version:version, test_version:"6.1", test_version2:"6.1.2" ) ) fix = '6.1.3';

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


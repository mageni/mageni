###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_panos_pan_sa-2016_0012.nasl 3710 2016-07-15 09:51:21Z mime $
#
# Palo Alto PAN-OS Local privilege escalation (PAN-SA-2016-0012)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105811");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_cve_id("CVE-2016-1712");
  script_version("$Revision: 12363 $");

  script_name("Palo Alto PAN-OS Local privilege escalation (PAN-SA-2016-0012)");

  script_xref(name:"URL", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/45");

  script_tag(name:"summary", value:"Palo Alto Networks firewalls do not properly sanitize the root_reboot local invocation which can potentially allow executing code with higher privileges");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Update to PAN-OS 5.0.19 and later, PAN-OS 5.1.12 and later, PAN-OS 6.0.14 and later, PAN-OS 6.1.12 and later, PAN-OS 7.0.8 or later");

  script_tag(name:"impact", value:"Exploitation of this privilege escalation is restricted to local users. Potential attackers would have to first obtain a shell on the device before they could attempt to escalate privileges through this vulnerability.");

  script_tag(name:"affected", value:"PAN-OS 5.0.18 and earlier, PAN-OS 5.1.11 and earlier, PAN-OS 6.0.13 and earlier, PAN-OS 6.1.11 and earlier, PAN-OS 7.0.7 and earlier");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-14 10:37:09 +0200 (Thu, 14 Jul 2016)");
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

if( version =~ "^5\.0" )
  fix = '5.0.19';
else if( version =~ "^5\.1" )
  fix = '5.1.12';
else if( version =~ "^6\.0" )
  fix = '6.0.14';
else if( version =~ "^6\.1" )
  fix = '6.1.12';
else if( version =~ "^7\.0" )
  fix = '7.0.8';

if( ! fix ) exit( 0 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = 'Installed version: ' + version + '\n' +
           'Fixed version:     ' + fix;

  if( model )
    report += '\nModel:             ' + model;

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


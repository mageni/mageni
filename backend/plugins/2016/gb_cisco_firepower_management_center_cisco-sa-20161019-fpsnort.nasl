###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firepower_management_center_cisco-sa-20161019-fpsnort.nasl 11922 2018-10-16 10:24:25Z asteins $
#
# Cisco Firepower Detection Engine HTTP Denial of Service Vulnerability
#
# Authors:
# Tameem Eissa <tameem.eissa@greenbone.net>
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

CPE = "cpe:/a:cisco:firepower_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.107064");
  script_cve_id("CVE-2016-6439");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 11922 $");
  script_name("Cisco Firepower Detection Engine HTTP Denial of Service Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161019-fpsnort");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"See the referenced vendor advisory for a solution.");
  script_tag(name:"summary", value:"A vulnerability in the detection engine reassembly of HTTP packets for Cisco Firepower System
  Software could allow an unauthenticated, remote attacker to cause a denial of service (DoS)
  condition due to the Snort process unexpectedly restarting.

  The vulnerability is due to improper handling of an HTTP packet stream. An attacker could exploit
  this vulnerability by sending a crafted HTTP packet stream to the detection engine on the targeted
  device. An exploit could allow the attacker to cause a DoS condition if the Snort process restarts
  and traffic inspection is bypassed or traffic is dropped.

  Cisco has released software updates that address this vulnerability. There are no workarounds that
  address this vulnerability.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-10-16 12:24:25 +0200 (Tue, 16 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-10-20 14:31:59 +0200 (Thu, 20 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firepower_management_center_version.nasl");
  script_mandatory_keys("cisco_firepower_management_center/version");
  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

affected = make_list(
                '5.3.0',
                '5.3.0.2',
                '5.3.0.3',
                '5.3.0.4',
                '5.3.1',
                '5.3.1.3',
                '5.3.1.4',
                '5.3.1.5',
                '5.3.1.6',
                '5.4',
                '5.4.1.3',
                '5.4.1.5',
                '5.4.1.4',
                '5.4.1.2',
                '5.4.1.1',
                '5.4.1',
                '5.4.0',
                '5.4.0.2',
                '5.4.1.6',
                '6.0',
                '6.0.0',
                '6.0.1',
                '6.0.0.1',
                '6.0.0.0' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "See advisory" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );


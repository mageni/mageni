###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_cisco_firesight_cisco-sa-20160727-firesight.nasl 12391 2018-11-16 16:12:15Z cfischer $
#
# Cisco FireSIGHT System Software Snort Rule Bypass Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:cisco:firesight_management_center";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106159");
  script_cve_id("CVE-2016-1463");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12391 $");

  script_name("Cisco FireSIGHT System Software Snort Rule Bypass Vulnerability");

  script_xref(name:"URL", value:"http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20160727-firesight");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Upgrade to Cisco FireSIGHT System Software
 version 6.1.0 or later.");

  script_tag(name:"summary", value:"A vulnerability in Snort rule detection in Cisco FireSIGHT System
Software could allow an unauthenticated, remote attacker to bypass configured rules that use Snort detection.

The vulnerability is due to improper handling of HTTP header parameters. An attacker could exploit this
vulnerability by sending a crafted HTTP packet to the affected device. An exploit could allow the attacker
to bypass configured rules that use Snort detection.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"last_modification", value:"$Date: 2018-11-16 17:12:15 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-07-29 12:50:14 +0700 (Fri, 29 Jul 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("CISCO");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_cisco_firesight_management_center_version.nasl", "gb_cisco_firesight_management_center_http_detect.nasl");
  script_mandatory_keys("cisco_firesight_management_center/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE, nofork:TRUE ) ) exit( 0 );

affected = make_list(
		'5.3.0',
		'5.3.1',
		'5.4.0',
		'6.0.0',
		'6.0.1' );

foreach af ( affected )
{
  if( version == af )
  {
    report = report_fixed_ver(  installed_version:version, fixed_version: "6.1.0" );
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );


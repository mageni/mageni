###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_juniper_screenos_JSA10759.nasl 12363 2018-11-15 09:51:15Z asteins $
#
# ScreenOS OpenSSL Security Updates
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

CPE = "cpe:/o:juniper:screenos";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140020");
  script_cve_id("CVE-2016-0703", "CVE-2016-0800", "CVE-2016-2108", "CVE-2015-3195", "CVE-2016-0704", "CVE-2016-6305", "CVE-2016-0797", "CVE-2016-2105", "CVE-2016-2106", "CVE-2016-2182", "CVE-2016-6306");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12363 $");

  script_name("ScreenOS OpenSSL Security Updates");

  script_xref(name:"URL", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10759");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution", value:"Update to ScreenOS 6.3.0r23 or newer.");

  script_tag(name:"summary", value:"The OpenSSL project has published a set of security advisories for vulnerabilities resolved in the OpenSSL library in December 2015, March, May, June, August and September 2016. ScreenOS is potentially affected by many of these issues.");
  script_tag(name:"affected", value:"ScreenOS < 6.3.0r23.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-15 10:51:15 +0100 (Thu, 15 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-10-26 15:11:39 +0200 (Wed, 26 Oct 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_screenos_version.nasl");
  script_mandatory_keys("ScreenOS/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

display_version = version;

version = str_replace( string:version, find:"r", replace:"." );
version = str_replace( string:version, find:"-", replace:"." );

display_fix = '6.3.0r23';

if( version_is_less( version:version, test_version:'6.3.0.23' ) )
{
  report = report_fixed_ver( installed_version:display_version, fixed_version:display_fix );

  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


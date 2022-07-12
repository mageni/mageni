###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortigate_FG-IR-16-023.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# FortiOS: Cookie Parser Buffer Overflow Vulnerability
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

CPE = "cpe:/h:fortinet:fortigate";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105875");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12096 $");
  script_cve_id("CVE-2016-6909");

  script_name("FortiOS: Cookie Parser Buffer Overflow Vulnerability");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-16-023");

  script_tag(name:"impact", value:"This vulnerability, when exploited by a crafted HTTP request, can result in execution control being taken over.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to release 5.x.
Upgrade to release 4.3.9 or above for models not compatible with FortiOS 5.x.");

  script_tag(name:"summary", value:"FortiGate firmware (FOS) released before Aug 2012 has a cookie parser buffer overflow vulnerability.");

  script_tag(name:"affected", value:"FortiGate (FOS):

4.3.8 and below

4.2.12 and below

4.1.10 and below");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-18 11:05:04 +0200 (Thu, 18 Aug 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_fortigate_version.nasl");
  script_mandatory_keys("fortigate/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( version =~ "^4\.1\." ) fix = '4.1.11';
if( version =~ "^4\.2\." ) fix = '4.2.13';
if( version =~ "^4\.3\." ) fix = '4.3.9';

if( ! fix ) exit( 99 );

if( version_is_less( version:version, test_version:fix ) )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );


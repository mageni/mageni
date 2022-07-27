###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortimanager_FG-IR-16-055.nasl 12106 2018-10-26 06:33:36Z cfischer $
#
# FortiManager TLS certificate validation failure
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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

CPE = "cpe:/h:fortinet:fortimanager";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140165");
  script_version("$Revision: 12106 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-02-17 11:01:22 +0100 (Fri, 17 Feb 2017)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");

  script_cve_id("CVE-2016-8495");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("FortiManager TLS certificate validation failure");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("FortiOS Local Security Checks");
  script_dependencies("gb_fortimanager_version.nasl");
  script_mandatory_keys("fortimanager/version");

  script_tag(name:"summary", value:"FortiManager does not properly validate TLS certificates when probing for devices to administer. This leads to potential pre-shared secret exposure.");
  script_tag(name:"impact", value:"Credentials exposure.");

  script_tag(name:"affected", value:"FortiManager 5.0.6 to 5.2.7 and 5.4.0 to 5.4.1.");

  script_tag(name:"solution", value:"Upgrade to FMG 5.2.8 and 5.4.2");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_xref(name:"URL", value:"https://fortiguard.com/psirt/FG-IR-16-055");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if( ! version = get_app_version( cpe: CPE ) )
  exit( 0 );

if( version_in_range( version: version, test_version: "5.0.6", test_version2: "5.2.7" ) )
  fix = '5.2.8';
else if( version_in_range( version: version, test_version: "5.4.0", test_version2: "5.4.1" ) )
  fix = '5.4.2';
else
  exit( 99 );

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit(99 );


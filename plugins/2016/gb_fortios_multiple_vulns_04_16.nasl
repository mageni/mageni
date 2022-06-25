###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_fortios_multiple_vulns_04_16.nasl 12051 2018-10-24 09:14:54Z asteins $
#
# FortiOS: Multiple Vulnerabilities
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

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105594");
  script_cve_id("CVE-2015-3626");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_version("$Revision: 12051 $");

  script_name("FortiOS: Multiple Vulnerabilities");

  script_xref(name:"URL", value:"http://fortiguard.com/advisory/dhcp-hostname-html-injection");
  script_xref(name:"URL", value:"http://fortiguard.com/advisory/fortios-open-redirect-vulnerability");

  script_tag(name:"impact", value:"Open redirect/Cross Site Scripting");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"solution", value:"Upgrade to one the following FortiOS versions:
5.0 branch: 5.0.13 or above
5.2 branch: 5.2.4 or above
5.4 branch: 5.4.0 or above

4.3 and lower branches are not affected by this vulnerability.");

  script_tag(name:"summary", value:"FortiOS is prone to multiple vulnerabilities.

  - It is possible to inject malicious script through the DHCP HOSTNAME option. The malicious script code is injected into the device's `DHCP Monitor` page (System->Monitor->DHCP Monitor) on the web-based interface which is accessible by the webui administrators.

  - The FortiOS webui accepts a user-controlled input that specifies a link to an external site, and uses that link in a redirect. The redirect input parameter is also prone to a cross site scripting.");

  script_tag(name:"affected", value:"5.0 branch: < 5.0.13
5.2 branch: < 5.2.4");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-24 11:14:54 +0200 (Wed, 24 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-04-04 11:42:25 +0200 (Mon, 04 Apr 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("FortiOS Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("forti/FortiOS/version");

  exit(0);
}

include("version_func.inc");

if( ! version = get_kb_item( "forti/FortiOS/version" )) exit( 0 );

if( version_in_range( version:version, test_version:"5.0", test_version2:"5.0.12" ) ) fix = '5.0.13';
if( version_in_range( version:version, test_version:"5.2", test_version2:"5.2.3" ) )  fix = '5.2.4';

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );
}

exit( 99 );

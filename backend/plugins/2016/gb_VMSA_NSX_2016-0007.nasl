###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_VMSA_NSX_2016-0007.nasl 12083 2018-10-25 09:48:10Z cfischer $
#
# VMSA-2016-0007: VMware NSX product updates address a critical information disclosure vulnerability
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
  script_oid("1.3.6.1.4.1.25623.1.0.105754");
  script_cve_id("CVE-2016-2079");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 12083 $");
  script_name("VMSA-2016-0007: VMware NSX product updates address a critical information disclosure vulnerability");

  script_xref(name:"URL", value:"http://www.vmware.com/security/advisories/VMSA-2016-0007.html");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version/build is present on the target host.");

  script_tag(name:"insight", value:"VMware NSX with SSL-VPN enabled contain a critical input validation vulnerability. This issue may allow a remote attacker
to gain access to sensitive information.");

  script_tag(name:"solution", value:"Apply the missing update.");

  script_tag(name:"summary", value:"VMware NSX product updates address a critical information disclosure vulnerability.");

  script_tag(name:"affected", value:"NSX 6.2 prior to 6.2.3

NSX 6.1 prior to 6.1.7");

  script_tag(name:"last_modification", value:"$Date: 2018-10-25 11:48:10 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-06-10 12:47:00 +0200 (Fri, 10 Jun 2016)");
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_family("VMware Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_dependencies("gb_vmware_nsx_version.nasl");
  script_mandatory_keys("vmware_nsx/version");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

cpe = 'cpe:/a:vmware:nsx';

if( ! version = get_app_version( cpe:cpe ) ) exit( 0 );

if( version_in_range( version:version, test_version:"6.2", test_version2:"6.2.2" ) ) fix = '6.2.3';
if( version_in_range( version:version, test_version:"6.1", test_version2:"6.1.6" ) ) fix = '6.1.7';

if( fix )
{
  report = report_fixed_ver( installed_version:version, fixed_version:fix );
  security_message( port:0, data:report );
  exit( 0 );

}

exit(99);
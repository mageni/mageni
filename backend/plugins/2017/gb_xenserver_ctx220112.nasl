###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx220112.nasl 11863 2018-10-12 09:42:02Z mmartin $
#
# Citrix XenServer Multiple Security Updates (CTX220112)
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.140127");
  script_cve_id("CVE-2017-5572", "CVE-2017-5573", "CVE-2015-5300", "CVE-2015-7704", "CVE-2015-7705");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_version("$Revision: 11863 $");

  script_name("Citrix XenServer Multiple Security Updates (CTX220112)");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX220112");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"Several security issues have been identified within Citrix XenServer. These issues could, if exploited, allow
an authenticated administrator to perform a denial-of-service attack against the host, even when that administrator has a less-privileged RBAC role
(e.g. read-only).  In addition, the issues could permit an attacker with the ability to influence NTP traffic on the management network to disrupt
time synchronization on the host until the next reboot.

The following vulnerabilities have been addressed:

  CVE-2017-5572 (Low): Authenticated read-only administrator can corrupt host database
  CVE-2017-5573 (Low): Authenticated read-only administrator can cancel tasks of other administrators
  CVE-2015-5300, CVE-2015-7704, CVE-2015-7705 (Low): NTP updates.

Customers who have not enabled NTP are unaffected by the NTP issues.
Customers who have not enabled RBAC are unaffected by the RBAC issues.
Customers using Citrix XenServer 6.0.2 in the Common Criteria configuration are unaffected by the RBAC issues.");

  script_tag(name:"affected", value:"XenServer 7.0
XenServer 6.5
XenServer 6.2.0
XenServer 6.0.2");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 11:42:02 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-01-26 10:36:18 +0100 (Thu, 26 Jan 2017)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");
include("citrix_version_func.inc");

if( ! version = get_app_version( cpe:CPE ) ) exit( 0 );

if( ! hotfixes = get_kb_item("xenserver/patches") ) exit( 0 );

patches = make_array();

patches['7.0.0'] = make_list( 'XS70E018',    'XS70E025' );
patches['6.5.0'] = make_list( 'XS65ESP1040', 'XS65ESP1047' );
patches['6.2.0'] = make_list( 'XS62ESP1051', 'XS62ESP1055' );
patches['6.0.2'] = make_list( 'XS602ECC036' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );

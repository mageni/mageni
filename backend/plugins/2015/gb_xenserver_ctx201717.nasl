###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx201717.nasl 11872 2018-10-12 11:22:41Z cfischer $
#
# Vulnerability in Citrix XenServer Could Result in Information Disclosure (CTX201717)
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105336");
  script_cve_id("CVE-2015-5165");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_version("$Revision: 11872 $");

  script_name("Vulnerability in Citrix XenServer Could Result in Information Disclosure (CTX201717)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX201717");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A vulnerability has been identified in Citrix XenServer which could, if exploited, allow a malicious administrator of an
HVM guest VM to obtain meta-data about their own VM. Citrix is presently unaware of any meta-data that might be leaked that would be of value to a malicious
guest administrator.

In non-default configurations, where the RTL8139 guest network device has been configured to enable offload and the Citrix PV guest drivers are not active, it may
also be possible for a remote attacker to obtain information from the HVM guest.");

  script_tag(name:"affected", value:"This issue affects all supported versions of Citrix XenServer up to and including Citrix XenServer 6.5 Service Pack 1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2015-08-28 14:51:58 +0200 (Fri, 28 Aug 2015)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
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

patches['6.5.0'] = make_list( 'XS65ESP1009', 'XS65E014' );
patches['6.2.0'] = make_list( 'XS62ESP1032' );
patches['6.1.0'] = make_list( 'XS61E058' );
patches['6.0.2'] = make_list( 'XS602E046', 'XS602ECC022' );
patches['6.0.0'] = make_list( 'XS60E051' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );


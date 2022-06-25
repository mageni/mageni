###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx212736.nasl 12149 2018-10-29 10:48:30Z asteins $
#
# Citrix XenServer Multiple Security Updates (CTX212736)
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.105732");
  script_cve_id("CVE-2016-3710", "CVE-2016-3712", "CVE-2016-2107", "CVE-2016-2108");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12149 $");

  script_name("Citrix XenServer Multiple Security Updates (CTX212736)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX212736");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer that may allow a malicious administrator of a guest VM (depending on configuration) or an attacker on the management network to compromise the host.");
  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including Citrix XenServer 6.5 Service Pack 1.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-29 11:48:30 +0100 (Mon, 29 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-05-26 12:29:51 +0200 (Thu, 26 May 2016)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
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

patches['6.5.0'] = make_list( 'XS65ESP1032', 'XS65ESP1033' );
patches['6.2.0'] = make_list( 'XS62ESP1044' );
patches['6.1.0'] = make_list( 'XS61E070' );
patches['6.0.2'] = make_list( 'XS602E055', 'XS602ECC032' );
patches['6.0.0'] = make_list( 'XS60E061' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );


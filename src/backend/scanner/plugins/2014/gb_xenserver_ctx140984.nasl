###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx140984.nasl 11867 2018-10-12 10:48:11Z cfischer $
#
# Citrix XenServer Multiple Security Updates (CTX140984)
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2014 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.105145");
  script_bugtraq_id(68070, 68659, 68660);
  script_cve_id("CVE-2014-4021", "CVE-2014-4947", "CVE-2014-4948");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 11867 $");

  script_name("Citrix XenServer Multiple Security Updates (CTX140984)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX140984");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer.
These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including Citrix
XenServer 6.2 Service Pack 1.

The following vulnerabilities have been addressed:

  - CVE-2014-4021: Citrix XenServer potential guest information leak through hypervisor page reuse

  - CVE-2014-4947: Buffer overflow in Citrix XenServer HVM graphics console support

  - CVE-2014-4948: Citrix XenServer guest denial of service and information leak through guest VHD modification");

  script_tag(name:"affected", value:"Citrix XenServer 6.2 Service Pack 1,

Citrix XenServer 6.1,

Citrix XenServer 6.0.2

Citrix XenServer 6.0.0");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-10-12 12:48:11 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2014-12-18 17:37:46 +0100 (Thu, 18 Dec 2014)");
  script_category(ACT_GATHER_INFO);
  script_family("Citrix Xenserver Local Security Checks");
  script_copyright("This script is Copyright (C) 2014 Greenbone Networks GmbH");
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

patches['6.2.0'] = make_list( 'XS62ESP1008' );
patches['6.1.0'] = make_list( 'XS61E041', 'XS61E040' );
patches['6.0.2'] = make_list( 'XS602E035','XS602ECC011', 'XS602ECC010' );
patches['6.0.0'] = make_list( 'XS60E039', 'XS60E038' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );


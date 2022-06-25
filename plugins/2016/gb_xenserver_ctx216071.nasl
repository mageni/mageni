###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx216071.nasl 12431 2018-11-20 09:21:00Z asteins $
#
# Citrix XenServer Multiple Security Updates (CTX216071)
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
  script_oid("1.3.6.1.4.1.25623.1.0.105895");
  script_cve_id("CVE-2016-7092", "CVE-2016-7093", "CVE-2016-7094", "CVE-2016-7154");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 12431 $");

  script_name("Citrix XenServer Multiple Security Updates (CTX216071)");

  script_xref(name:"URL", value:"http://support.citrix.com/article/CTX216071");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes");
  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer that may allow malicious privileged code running within a guest VM to compromise the host.
The following vulnerabilities have been addressed:

  - CVE-2016-7092 (High): x86: Disallow L3 recursive pagetable for 32-bit guests

  - CVE-2016-7093 (High): x86: Mishandling of instruction pointer truncation during emulation

  - CVE-2016-7094 (Medium): x86 HVM: Overflow of sh_ctxt->seg_reg[]

  - CVE-2016-7154 (High): use after free in FIFO event channel code");
  script_tag(name:"affected", value:"These vulnerabilities affect all currently supported versions of Citrix XenServer up to and including Citrix XenServer 7.0.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_tag(name:"last_modification", value:"$Date: 2018-11-20 10:21:00 +0100 (Tue, 20 Nov 2018) $");
  script_tag(name:"creation_date", value:"2016-09-19 13:43:16 +0200 (Mon, 19 Sep 2016)");
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

patches['7.0.0'] = make_list( 'XS70E012' );
patches['6.5.0'] = make_list( 'XS65ESP1038' );
patches['6.2.0'] = make_list( 'XS62ESP1048' );
patches['6.1.0'] = make_list( 'XS61E073' );
patches['6.0.2'] = make_list( 'XS602E057', 'XS602ECC034' );
patches['6.0.0'] = make_list( 'XS60E063' );

report_if_citrix_xenserver_is_vulnerable( version:version,
                                          hotfixes:hotfixes,
                                          patches:patches );

exit( 99 );


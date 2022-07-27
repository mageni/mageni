###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx225941.nasl 11977 2018-10-19 07:28:56Z mmartin $
#
# Citrix XenServer Multiple Security Updates (CTX225941)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2017 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
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
  script_oid("1.3.6.1.4.1.25623.1.0.140303");
  script_version("$Revision: 11977 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 09:28:56 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-08-16 09:04:44 +0700 (Wed, 16 Aug 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-12134", "CVE-2017-12135", "CVE-2017-12136", "CVE-2017-12137", "CVE-2017-12855");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Multiple Security Updates (CTX225941)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix XenServer that may allow a malicious administrator of a guest VM to compromise the host:

  - CVE-2017-12134: (High) linux: Fix Xen block IO merge-ability calculation.

  - CVE-2017-12135: (Medium) multiple problems with transitive grants.

  - CVE-2017-12136: (High) grant_table: Race conditions with maptrack free list handling.

  - CVE-2017-12137: (High) x86: PV privilege escalation via map_grant_ref.

  - CVE-2017-12855: (Low) grant_table: possibly premature clearing of GTF_writing / GTF_reading.");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"affected", value:"XenServer versions 7.2, 7.1, 7.0, 6.5, 6.2.0, 6.0.2.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX225941");

  exit(0);
}

include("citrix_version_func.inc");
include("host_details.inc");
include("misc_func.inc");

if (!version = get_app_version(cpe: CPE))
  exit(0);

if (!hotfixes = get_kb_item("xenserver/patches"))
  exit(0);

patches = make_array();

patches['7.2.0'] = make_list('XS72E004', 'XS72E005');
patches['7.1.0'] = make_list('XS71E013', 'XS71E014');
patches['7.0.0'] = make_list('XS70E039', 'XS70E040');
patches['6.5.0'] = make_list('XS65ESP1059', 'XS65ESP1060');
patches['6.2.0'] = make_list('XS62ESP1063');
patches['6.0.2'] = make_list('XS602ECC047');

report_if_citrix_xenserver_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);

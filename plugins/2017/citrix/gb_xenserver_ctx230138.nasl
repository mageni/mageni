###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx230138.nasl 11983 2018-10-19 10:04:45Z mmartin $
#
# Citrix XenServer Multiple Security Updates (CTX230138)
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
  script_oid("1.3.6.1.4.1.25623.1.0.140576");
  script_version("$Revision: 11983 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 12:04:45 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-12-05 09:08:18 +0700 (Tue, 05 Dec 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-7980", "CVE-2017-15592", "CVE-2017-17044", "CVE-2017-17045");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Multiple Security Updates (CTX230138)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A number of security vulnerabilities have been identified in Citrix
XenServer that may allow a malicious administrator of an HVM guest VM to compromise the host.

  - CVE-2017-7980: code execution via overflow in Cirrus Logic emulation

  - CVE-2017-15592: Incorrect handling of self-linear shadow mappings with translated guests

  - CVE-2017-17044: Infinite loop due to missing PoD error checking

  - CVE-2017-17045: Missing p2m error checking in PoD code");

  script_tag(name:"affected", value:"XenServer versions 7.2, 7.1, 7.0, 6.5, 6.2.0 and 6.0.2.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX230138");

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

patches['7.2.0'] = make_list('XS72E010', 'XS72E012');
patches['7.1.0'] = make_list('XS71E018', 'XS71E019');
patches['7.0.0'] = make_list('XS70E048', 'XS70E049');
patches['6.5.0'] = make_list('XS65ESP1064');
patches['6.2.0'] = make_list('XS62ESP1066');
patches['6.0.2'] = make_list('XS602ECC050');

report_if_citrix_xenserver_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);

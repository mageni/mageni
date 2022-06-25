###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx223291.nasl 11874 2018-10-12 11:28:04Z mmartin $
#
# Citrix XenServer Multiple Security Updates (CTX223291)
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
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

CPE = "cpe:/a:citrix:xenserver";

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106911");
  script_version("$Revision: 11874 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-12 13:28:04 +0200 (Fri, 12 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-28 10:07:10 +0700 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-8903", "CVE-2017-8904", "CVE-2017-8905");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Multiple Security Updates (CTX223291)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A number of security issues have been identified within Citrix XenServer.
These issues could, if exploited, allow a malicious administrator of a PV guest VM to compromise the host. The
issues have the identifiers:

  - CVE-2017-8903 (High): x86: 64bit PV guest breakout via pagetable use-after-mode-change

  - CVE-2017-8904 (High): grant transfer allows PV guest to elevate privileges

  - CVE-2017-8905 (Low): possible memory corruption via failsafe callback");

  script_tag(name:"vuldetect", value:"Check the installed hotfixes.");

  script_tag(name:"affected", value:"XenServer versions 7.1, 7.0, 6.5, 6.2.0, 6.0.2.");

  script_tag(name:"solution", value:"Apply the hotfix referenced in the advisory.");

  script_xref(name:"URL", value:"https://support.citrix.com/article/CTX223291");

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

patches['7.1.0'] = make_list('XS71E007');
patches['7.0.0'] = make_list('XS70E034');
patches['6.5.0'] = make_list('XS65ESP1054');
patches['6.2.0'] = make_list('XS62ESP1060');
patches['6.0.2'] = make_list('XS602ECC044');

report_if_citrix_xenserver_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);

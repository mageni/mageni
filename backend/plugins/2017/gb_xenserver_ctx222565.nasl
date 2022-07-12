###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_xenserver_ctx222565.nasl 11982 2018-10-19 08:49:21Z mmartin $
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
  script_oid("1.3.6.1.4.1.25623.1.0.106912");
  script_version("$Revision: 11982 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-19 10:49:21 +0200 (Fri, 19 Oct 2018) $");
  script_tag(name:"creation_date", value:"2017-06-28 10:07:10 +0700 (Wed, 28 Jun 2017)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2017-7228", "CVE-2016-10013");

  script_tag(name:"qod_type", value:"package");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Citrix XenServer Multiple Security Updates (CTX223291)");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("Citrix Xenserver Local Security Checks");
  script_dependencies("gb_xenserver_version.nasl");
  script_mandatory_keys("xenserver/product_version", "xenserver/patches");

  script_tag(name:"summary", value:"A number of security issues have been identified within Citrix XenServer.
The most significant of these issues could, if exploited, allow a malicious administrator of a 64-bit PV guest VM
to compromise the host. This issue has the identifier:

  - CVE-2017-7228 (High): x86: broken check in memory_exchange() permits PV guest breakout

In addition, an issue has been identified that, in certain deployments, allows a guest VM to perform a denial of
service attack against the host by repeatedly rebooting many times.

  - (Low): memory leak when destroying guest without PT devices

A further issue has been identified that, in certain deployments, might allow unprivileged code within a guest to
escalate its privilege level within that same guest.  This issue has the identifier:

  - CVE-2016-10013 (Low): x86: Mishandling of SYSCALL singlestep during emulation");

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

patches['7.1.0'] = make_list('XS71E006');
patches['7.0.0'] = make_list('XS70E032');
patches['6.5.0'] = make_list('XS65ESP1053');
patches['6.2.0'] = make_list('XS62ESP1059');
patches['6.0.2'] = make_list('XS602ECC043');

report_if_citrix_xenserver_is_vulnerable(version: version, hotfixes: hotfixes, patches: patches);

exit(99);

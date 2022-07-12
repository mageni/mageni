###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_1446.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 1446-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.891446");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2018-3639", "CVE-2018-3640");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1446-1] intel-microcode security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-07-27 00:00:00 +0200 (Fri, 27 Jul 2018)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2018/07/msg00038.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");
  script_tag(name:"affected", value:"intel-microcode on Debian Linux");
  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.20180703.2~deb8u1.

We recommend that you upgrade your intel-microcode packages.");
  script_tag(name:"summary", value:"Security researchers identified two software analysis methods that, if
used for malicious purposes, have the potential to improperly gather
sensitive data from multiple types of computing devices with different
vendors' processors and operating systems.

This update requires an update to the intel-microcode package, which
is non-free. Users who have already installed the version from
jessie-backports-sloppy do not need to upgrade.

CVE-2018-3639 - Speculative Store Bypass (SSB) - also known as Variant 4

Systems with microprocessors utilizing speculative execution and
speculative execution of memory reads before the addresses of all
prior memory writes are known may allow unauthorized disclosure of
information to an attacker with local user access via a side-channel
analysis.

CVE-2018-3640 - Rogue System Register Read (RSRE) - also known as
Variant 3a

Systems with microprocessors utilizing speculative execution and
that perform speculative reads of system registers may allow
unauthorized disclosure of system parameters to an attacker with
local user access via a side-channel analysis.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"intel-microcode", ver:"3.20180703.2~deb8u1", rls:"DEB8")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
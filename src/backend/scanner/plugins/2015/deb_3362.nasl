# OpenVAS Vulnerability Test
# $Id: deb_3362.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3362-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.703362");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-5278", "CVE-2015-5279", "CVE-2015-6815", "CVE-2015-6855");
  script_name("Debian Security Advisory DSA 3362-1 (qemu-kvm - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-09-18 00:00:00 +0200 (Fri, 18 Sep 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3362.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"qemu-kvm on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy), these problems have been fixed
in version 1.1.2+dfsg-6+deb7u11.

We recommend that you upgrade your qemu-kvm packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in qemu-kvm, a full
virtualization solution on x86 hardware.

CVE-2015-5278
Qinghao Tang of QIHU 360 Inc. discovered an infinite loop issue in
the NE2000 NIC emulation. A privileged guest user could use this
flaw to mount a denial of service (QEMU process crash).

CVE-2015-5279
Qinghao Tang of QIHU 360 Inc. discovered a heap buffer overflow flaw
in the NE2000 NIC emulation. A privileged guest user could use this
flaw to mount a denial of service (QEMU process crash), or
potentially to execute arbitrary code on the host with the
privileges of the hosting QEMU process.

CVE-2015-6815
Qinghao Tang of QIHU 360 Inc. discovered an infinite loop issue in
the e1000 NIC emulation. A privileged guest user could use this flaw
to mount a denial of service (QEMU process crash).

CVE-2015-6855
Qinghao Tang of QIHU 360 Inc. discovered a flaw in the IDE
subsystem in QEMU occurring while executing IDE's
WIN_READ_NATIVE_MAX command to determine the maximum size of a
drive. A privileged guest user could use this flaw to mount a
denial of service (QEMU process crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kvm", ver:"1.1.2+dfsg-6+deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.1.2+dfsg-6+deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-kvm-dbg", ver:"1.1.2+dfsg-6+deb7u11", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
# OpenVAS Vulnerability Test
# $Id: deb_3348.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3348-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703348");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3214", "CVE-2015-5154", "CVE-2015-5165", "CVE-2015-5225",
                  "CVE-2015-5745");
  script_name("Debian Security Advisory DSA 3348-1 (qemu - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-09-02 00:00:00 +0200 (Wed, 02 Sep 2015)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3348.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"qemu on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.1.2+dfsg-6a+deb7u9. The oldstable
distribution is only affected by CVE-2015-5165 and CVE-2015-5745
.

For the stable distribution (jessie), these problems have been fixed in
version 1:2.1+dfsg-12+deb8u2.

For the unstable distribution (sid), these problems have been fixed in
version 1:2.4+dfsg-1a.

We recommend that you upgrade your qemu packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in qemu, a fast processor emulator.

CVE-2015-3214
Matt Tait of Google's Project Zero security team discovered a flaw
in the QEMU i8254 PIT emulation. A privileged guest user in a guest
with QEMU PIT emulation enabled could potentially use this flaw to
execute arbitrary code on the host with the privileges of the
hosting QEMU process.

CVE-2015-5154
Kevin Wolf of Red Hat discovered a heap buffer overflow flaw in the
IDE subsystem in QEMU while processing certain ATAPI commands. A
privileged guest user in a guest with the CDROM drive enabled could
potentially use this flaw to execute arbitrary code on the host with
the privileges of the hosting QEMU process.

CVE-2015-5165
Donghai Zhu discovered that the QEMU model of the RTL8139 network
card did not sufficiently validate inputs in the C+ mode offload
emulation, allowing a malicious guest to read uninitialized memory
from the QEMU process's heap.

CVE-2015-5225
Mr Qinghao Tang from QIHU 360 Inc. and Mr Zuozhi from Alibaba Inc
discovered a buffer overflow flaw in the VNC display driver leading
to heap memory corruption. A privileged guest user could use this
flaw to mount a denial of service (QEMU process crash), or
potentially to execute arbitrary code on the host with the
privileges of the hosting QEMU process.

CVE-2015-5745
A buffer overflow vulnerability was discovered in the way QEMU
handles the virtio-serial device. A malicious guest could use this
flaw to mount a denial of service (QEMU process crash).");
  script_tag(name:"vuldetect", value:"This check tests the installed
software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u9", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
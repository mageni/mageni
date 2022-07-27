###############################################################################
# OpenVAS Vulnerability Test
# $Id: deb_dla_842.nasl 14281 2019-03-18 14:53:48Z cfischer $
#
# Auto-generated from advisory DLA 842-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.890842");
  script_version("$Revision: 14281 $");
  script_cve_id("CVE-2016-9921", "CVE-2017-2615", "CVE-2017-2620", "CVE-2017-5898", "CVE-2017-5973");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 842-1] qemu-kvm security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:53:48 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2018-01-08 00:00:00 +0100 (Mon, 08 Jan 2018)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00033.html");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2018 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"qemu-kvm on Debian Linux");
  script_tag(name:"solution", value:"For Debian 7 'Wheezy', these problems have been fixed in version
1.1.2+dfsg-6+deb7u20.

We recommend that you upgrade your qemu-kvm packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered in qemu-kvm, a full
virtualization solution for Linux hosts on x86 hardware with x86 guests.

CVE-2017-2615

The Cirrus CLGD 54xx VGA Emulator in qemu-kvm is vulnerable to an
out-of-bounds access issue. It could occur while copying VGA data
via bitblt copy in backward mode.

A privileged user inside guest could use this flaw to crash the
Qemu process resulting in DoS OR potentially execute arbitrary
code on the host with privileges of qemu-kvm process on the host.

CVE-2017-2620

The Cirrus CLGD 54xx VGA Emulator in qemu-kvm is vulnerable to an
out-of-bounds access issue. It could occur while copying VGA data
in cirrus_bitblt_cputovideo.

A privileged user inside guest could use this flaw to crash the
Qemu process resulting in DoS OR potentially execute arbitrary
code on the host with privileges of qemu-kvm process on the host.

CVE-2017-5898

The CCID Card device emulator support is vulnerable to an integer
overflow flaw. It could occur while passing message via
command/responses packets to and from the host.

A privileged user inside guest could use this flaw to crash the
qemu-kvm process on the host resulting in a DoS.

This issue does not affect the qemu-kvm binaries in Debian but we
apply the patch to the sources to stay in sync with the qemu
package.

CVE-2017-5973

The USB xHCI controller emulator support in qemu-kvm is vulnerable
to an infinite loop issue. It could occur while processing control
transfer descriptors' sequence in xhci_kick_epctx.

A privileged user inside guest could use this flaw to crash the
qemu-kvm process resulting in a DoS.

This update also updates the fix CVE-2016-9921 since it was too strict
and broke certain guests.");
  script_tag(name:"vuldetect", value:"This check tests the installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"kvm", ver:"1.1.2+dfsg-6+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-kvm", ver:"1.1.2+dfsg-6+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-kvm-dbg", ver:"1.1.2+dfsg-6+deb7u20", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
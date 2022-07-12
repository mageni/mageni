# OpenVAS Vulnerability Test
# $Id: deb_3284.nasl 14278 2019-03-18 14:47:26Z cfischer $
# Auto-generated from advisory DSA 3284-1 using nvtgen 1.0
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
  script_oid("1.3.6.1.4.1.25623.1.0.703284");
  script_version("$Revision: 14278 $");
  script_cve_id("CVE-2015-3209", "CVE-2015-4037", "CVE-2015-4103", "CVE-2015-4104",
                  "CVE-2015-4105", "CVE-2015-4106");
  script_name("Debian Security Advisory DSA 3284-1 (qemu - security update)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-18 15:47:26 +0100 (Mon, 18 Mar 2019) $");
  script_tag(name:"creation_date", value:"2015-06-13 00:00:00 +0200 (Sat, 13 Jun 2015)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  script_xref(name:"URL", value:"http://www.debian.org/security/2015/dsa-3284.html");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");
  script_tag(name:"affected", value:"qemu on Debian Linux");
  script_tag(name:"solution", value:"For the oldstable distribution (wheezy),
these problems have been fixed in version 1.1.2+dfsg-6a+deb7u8. Only CVE-2015-3209
and CVE-2015-4037 affect oldstable.

For the stable distribution (jessie), these problems have been fixed in
version 1:2.1+dfsg-12+deb8u1.

For the unstable distribution (sid), these problems have been fixed in
version 1:2.3+dfsg-6.

We recommend that you upgrade your qemu packages.");
  script_tag(name:"summary", value:"Several vulnerabilities were discovered
in qemu, a fast processor emulator.

CVE-2015-3209
Matt Tait of Google's Project Zero security team discovered a flaw
in the way QEMU's AMD PCnet Ethernet emulation handles multi-TMD
packets with a length above 4096 bytes. A privileged guest user in a
guest with an AMD PCNet ethernet card enabled can potentially use
this flaw to execute arbitrary code on the host with the privileges
of the hosting QEMU process.

CVE-2015-4037
Kurt Seifried of Red Hat Product Security discovered that QEMU's
user mode networking stack uses predictable temporary file names
when the -smb option is used. An unprivileged user can use this flaw
to cause a denial of service.

CVE-2015-4103
Jan Beulich of SUSE discovered that the QEMU Xen code does not
properly restrict write access to the host MSI message data field,
allowing a malicious guest to cause a denial of service.

CVE-2015-4104
Jan Beulich of SUSE discovered that the QEMU Xen code does not
properly restrict access to PCI MSI mask bits, allowing a malicious
guest to cause a denial of service.

CVE-2015-4105
Jan Beulich of SUSE reported that the QEMU Xen code enables
logging for PCI MSI-X pass-through error messages, allowing a
malicious guest to cause a denial of service.

CVE-2015-4106
Jan Beulich of SUSE discovered that the QEMU Xen code does not
properly restrict write access to the PCI config space for certain
PCI pass-through devices, allowing a malicious guest to cause a
denial of service, obtain sensitive information or potentially
execute arbitrary code.");
  script_tag(name:"vuldetect", value:"This check tests the
installed software version using the apt package manager.");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if((res = isdpkgvuln(pkg:"qemu", ver:"1.1.2+dfsg-6a+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-keymaps", ver:"1.1.2+dfsg-6a+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-system", ver:"1.1.2+dfsg-6a+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user", ver:"1.1.2+dfsg-6a+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-user-static", ver:"1.1.2+dfsg-6a+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}
if((res = isdpkgvuln(pkg:"qemu-utils", ver:"1.1.2+dfsg-6a+deb7u8", rls:"DEB7")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if (__pkg_match) {
  exit(99);
}
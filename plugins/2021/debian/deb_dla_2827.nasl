# Copyright (C) 2021 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.892827");
  script_version("2021-11-28T02:00:13+0000");
  script_cve_id("CVE-2019-8921", "CVE-2019-8922", "CVE-2021-41229");
  script_tag(name:"cvss_base", value:"3.3");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-11-29 10:38:15 +0000 (Mon, 29 Nov 2021)");
  script_tag(name:"creation_date", value:"2021-11-28 02:00:13 +0000 (Sun, 28 Nov 2021)");
  script_name("Debian LTS: Security Advisory for bluez (DLA-2827-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/11/msg00022.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2827-1");
  script_xref(name:"Advisory-ID", value:"DLA-2827-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1000262");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez'
  package(s) announced via the DLA-2827-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in BlueZ, the Linux Bluetooth
protocol stack. An attacker could cause a denial-of-service (DoS) or
leak information.

CVE-2019-8921

SDP infoleak, the vulnerability lies in the handling of a
SVC_ATTR_REQ by the SDP implementation of BlueZ. By crafting a
malicious CSTATE, it is possible to trick the server into
returning more bytes than the buffer actually holds, resulting in
leaking arbitrary heap data.

CVE-2019-8922

SDP Heap Overflow, this vulnerability lies in the SDP protocol
handling of attribute requests as well. By requesting a huge
number of attributes at the same time, an attacker can overflow
the static buffer provided to hold the response.

CVE-2021-41229

sdp_cstate_alloc_buf allocates memory which will always be hung in
the singly linked list of cstates and will not be freed. This will
cause a memory leak over time. The data can be a very large
object, which can be caused by an attacker continuously sending
sdp packets and this may cause the service of the target device to
crash.");

  script_tag(name:"affected", value:"'bluez' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
5.43-2+deb9u5.

We recommend that you upgrade your bluez packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bluetooth", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-cups", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-dbg", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-hcidump", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-obexd", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-test-scripts", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-test-tools", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth-dev", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3-dbg", ver:"5.43-2+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

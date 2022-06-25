# Copyright (C) 2020 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892240");
  script_version("2020-06-10T03:00:06+0000");
  script_cve_id("CVE-2020-0556");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-06-10 10:58:50 +0000 (Wed, 10 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-10 03:00:06 +0000 (Wed, 10 Jun 2020)");
  script_name("Debian LTS: Security Advisory for bluez (DLA-2240-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/06/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2240-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/953770");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez'
  package(s) announced via the DLA-2240-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that the BlueZ's HID and HOGP profile implementations
don't specifically require bonding between the device and the host.
Malicious devices can take advantage of this flaw to connect to a target
host and impersonate an existing HID device without security or to cause
an SDP or GATT service discovery to take place which would allow HID
reports to be injected to the input subsystem from a non-bonded source.

For the HID profile an new configuration option (ClassicBondedOnly) is
introduced to make sure that input connections only come from bonded
device connections. The options defaults to 'false' to maximize device
compatibility.

Note that as a result of the significant changes between the previous
version in Jessie (based on upstream release 5.23) and the available
patches to address this vulnerability, it was decided that a backport of
the bluez package from Debian 9 'Stretch' was the only viable way to
address the referenced vulnerability.");

  script_tag(name:"affected", value:"'bluez' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
5.43-2+deb9u2~deb8u1.

We recommend that you upgrade your bluez packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"bluetooth", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-cups", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-dbg", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-hcidump", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-obexd", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-test-scripts", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"bluez-test-tools", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth-dev", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libbluetooth3-dbg", ver:"5.43-2+deb9u2~deb8u1", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

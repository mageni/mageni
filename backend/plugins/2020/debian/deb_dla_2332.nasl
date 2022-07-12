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
  script_oid("1.3.6.1.4.1.25623.1.0.892332");
  script_version("2020-08-18T03:00:11+0000");
  script_cve_id("CVE-2020-12862", "CVE-2020-12863", "CVE-2020-12865", "CVE-2020-12867");
  script_tag(name:"cvss_base", value:"5.2");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:S/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-08-18 10:12:19 +0000 (Tue, 18 Aug 2020)");
  script_tag(name:"creation_date", value:"2020-08-18 03:00:11 +0000 (Tue, 18 Aug 2020)");
  script_name("Debian LTS: Security Advisory for sane-backends (DLA-2332-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/08/msg00029.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2332-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/961302");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'sane-backends'
  package(s) announced via the DLA-2332-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kevin Backhouse discovered multiple vulnerabilies in the epson2 and
epsonds backends of SANE, a library for scanners. A malicious remote
device could exploit these to trigger information disclosure, denial
of service and possibly remote code execution.

CVE-2020-12862

An out-of-bounds read in SANE Backends before 1.0.30 may allow a
malicious device connected to the same local network as the victim
to read important information, such as the ASLR offsets of the
program, aka GHSL-2020-082.

CVE-2020-12863

An out-of-bounds read in SANE Backends before 1.0.30 may allow a
malicious device connected to the same local network as the victim
to read important information, such as the ASLR offsets of the
program, aka GHSL-2020-083.

CVE-2020-12865

A heap buffer overflow in SANE Backends before 1.0.30 may allow a
malicious device connected to the same local network as the victim
to execute arbitrary code, aka GHSL-2020-084.

CVE-2020-12867

A NULL pointer dereference in sanei_epson_net_read in SANE
Backends before 1.0.30 allows a malicious device connected to the
same local network as the victim to cause a denial of service, aka
GHSL-2020-075.");

  script_tag(name:"affected", value:"'sane-backends' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.0.25-4.1+deb9u1.

We recommend that you upgrade your sane-backends packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libsane", ver:"1.0.25-4.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsane-common", ver:"1.0.25-4.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsane-dbg", ver:"1.0.25-4.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libsane-dev", ver:"1.0.25-4.1+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"sane-utils", ver:"1.0.25-4.1+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

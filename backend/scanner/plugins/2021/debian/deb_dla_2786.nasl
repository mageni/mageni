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
  script_oid("1.3.6.1.4.1.25623.1.0.892786");
  script_version("2021-10-18T08:03:29+0000");
  script_cve_id("CVE-2018-1000168", "CVE-2020-11080");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-10-18 10:42:08 +0000 (Mon, 18 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-03-05 13:58:00 +0000 (Tue, 05 Mar 2019)");
  script_tag(name:"creation_date", value:"2021-10-18 01:00:13 +0000 (Mon, 18 Oct 2021)");
  script_name("Debian LTS: Security Advisory for nghttp2 (DLA-2786-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/10/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2786-1");
  script_xref(name:"Advisory-ID", value:"DLA-2786-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nghttp2'
  package(s) announced via the DLA-2786-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issue have been discovered in nghttp2: server, proxy and client
implementing HTTP/2.

CVE-2018-1000168

An Improper Input Validation CWE-20 vulnerability found in ALTSVC frame handling
that can result in segmentation fault leading to denial of service. This attack
appears to be exploitable via network client.

CVE-2020-11080

The overly large HTTP/2 SETTINGS frame payload causes denial of service.
The proof of concept attack involves a malicious client constructing a SETTINGS
frame with a length of 14,400 bytes (2400 individual settings entries) over and over again.
The attack causes the CPU to spike at 100%.");

  script_tag(name:"affected", value:"'nghttp2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.18.1-1+deb9u2.

We recommend that you upgrade your nghttp2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libnghttp2-14", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnghttp2-dev", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libnghttp2-doc", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nghttp2", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nghttp2-client", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nghttp2-proxy", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"nghttp2-server", ver:"1.18.1-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

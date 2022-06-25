# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.892919");
  script_version("2022-02-14T02:00:05+0000");
  script_cve_id("CVE-2021-3177", "CVE-2021-4189");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2022-02-14 11:09:18 +0000 (Mon, 14 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-14 02:00:05 +0000 (Mon, 14 Feb 2022)");
  script_name("Debian LTS: Security Advisory for python2.7 (DLA-2919-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/02/msg00013.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2919-1");
  script_xref(name:"Advisory-ID", value:"DLA-2919-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7'
  package(s) announced via the DLA-2919-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two issues have been discovered in python2.7:

CVE-2021-3177

Python has a buffer overflow in PyCArg_repr in _ctypes/callproc.c, which may
lead to remote code execution in certain Python applications that accept
floating-point numbers as untrusted input.

CVE-2021-4189

A flaw was found in Python, specifically in the FTP (File Transfer Protocol)
client library when using it in PASV (passive) mode. The flaw lies in how
the FTP client trusts the host from PASV response by default. An attacker
could use this flaw to setup a malicious FTP server that can trick FTP
clients into connecting back to a given IP address and port. This could lead
to FTP client scanning ports which otherwise would not have been possible.
.
Instead of using the returned address, ftplib now uses the IP address we're
already connected to. For the rare user who wants an old behavior, set a
`trust_server_pasv_ipv4_address` attribute on your `ftplib.FTP` instance to
True.");

  script_tag(name:"affected", value:"'python2.7' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.7.13-2+deb9u6.

We recommend that you upgrade your python2.7 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"idle-python2.7", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-dbg", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-dev", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-minimal", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-stdlib", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-testsuite", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-dbg", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-dev", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-doc", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-examples", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.13-2+deb9u6", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

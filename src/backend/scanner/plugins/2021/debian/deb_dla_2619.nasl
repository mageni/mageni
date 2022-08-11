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
  script_oid("1.3.6.1.4.1.25623.1.0.892619");
  script_version("2021-04-06T03:00:13+0000");
  script_cve_id("CVE-2021-23336", "CVE-2021-3177", "CVE-2021-3426");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2021-04-06 10:08:15 +0000 (Tue, 06 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-06 03:00:13 +0000 (Tue, 06 Apr 2021)");
  script_name("Debian LTS: Security Advisory for python3.5 (DLA-2619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00005.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2619-1");
  script_xref(name:"Advisory-ID", value:"DLA-2619-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python3.5'
  package(s) announced via the DLA-2619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Three security issues have been discovered in python3.5:

CVE-2021-3177

Python 3.x has a buffer overflow in PyCArg_repr in _ctypes/callproc.c,
which may lead to remote code execution in certain Python applications that accept
floating-point numbers as untrusted input.
This occurs because sprintf is used unsafely.

CVE-2021-3426

Running `pydoc -p` allows other local users to extract arbitrary files.
The `/getfile?key=path` URL allows to read arbitrary file on the filesystem.

The fix removes the 'getfile' feature of the pydoc module which
could be abused to read arbitrary files on the disk (directory
traversal vulnerability).

CVE-2021-23336

The Python3.5 vulnerable to Web Cache Poisoning via urllib.parse.parse_qsl
and urllib.parse.parse_qs by using a vector called parameter cloaking. When
the attacker can separate query parameters using a semicolon, they can
cause a difference in the interpretation of the request between the proxy
(running with default configuration) and the server. This can result in malicious
requests being cached as completely safe ones, as the proxy would usually not
see the semicolon as a separator, and therefore would not include it in a cache
key of an unkeyed parameter.

**Attention, API-change!**
Please be sure your software is working properly if it uses `urllib.parse.parse_qs`
or `urllib.parse.parse_qsl`, `cgi.parse` or `cgi.parse_multipart`.

Earlier Python versions allowed using both semicolon and ``&`` as query parameter
separators in `urllib.parse.parse_qs` and `urllib.parse.parse_qsl`.
Due to security concerns, and to conform with
newer W3C recommendations, this has been changed to allow only a single
separator key, with ``&`` as the default. This change also affects
`cgi.parse` and `cgi.parse_multipart` as they use the affected
functions internally. For more details, please see their respective
documentation.");

  script_tag(name:"affected", value:"'python3.5' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.5.3-1+deb9u4.

We recommend that you upgrade your python3.5 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"idle-python3.5", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-dbg", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-dev", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-minimal", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-stdlib", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython3.5-testsuite", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-dbg", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-dev", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-doc", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-examples", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-minimal", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python3.5-venv", ver:"3.5.3-1+deb9u4", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

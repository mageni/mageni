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
  script_oid("1.3.6.1.4.1.25623.1.0.892628");
  script_version("2021-04-18T03:00:08+0000");
  script_cve_id("CVE-2019-16935", "CVE-2021-23336");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-04-19 10:12:59 +0000 (Mon, 19 Apr 2021)");
  script_tag(name:"creation_date", value:"2021-04-18 03:00:08 +0000 (Sun, 18 Apr 2021)");
  script_name("Debian LTS: Security Advisory for python2.7 (DLA-2628-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/04/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2628-1");
  script_xref(name:"Advisory-ID", value:"DLA-2628-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python2.7'
  package(s) announced via the DLA-2628-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security issues have been discovered in python2.7:

CVE-2019-16935

The documentation XML-RPC server in Python 2.7 has XSS via the server_title
field. This occurs in Lib/DocXMLRPCServer.py in Python 2.x, and in
Lib/xmlrpc/server.py in Python 3.x. If set_server_title is called with
untrusted input, arbitrary JavaScript can be delivered to clients that
visit the http URL for this server.

CVE-2021-23336

The Python2.7 vulnerable to Web Cache Poisoning via urllib.parse.parse_qsl
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

  script_tag(name:"affected", value:"'python2.7' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.7.13-2+deb9u5.

We recommend that you upgrade your python2.7 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"idle-python2.7", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-dbg", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-dev", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-minimal", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-stdlib", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libpython2.7-testsuite", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-dbg", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-dev", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-doc", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-examples", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"python2.7-minimal", ver:"2.7.13-2+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

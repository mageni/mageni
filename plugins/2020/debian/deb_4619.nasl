# Copyright (C) 2020 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704619");
  script_version("2020-02-07T04:00:05+0000");
  script_cve_id("CVE-2019-17570");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2020-02-07 04:00:05 +0000 (Fri, 07 Feb 2020)");
  script_tag(name:"creation_date", value:"2020-02-07 04:00:05 +0000 (Fri, 07 Feb 2020)");
  script_name("Debian: Security Advisory for libxmlrpc3-java (DSA-4619-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(9|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4619.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4619-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxmlrpc3-java'
  package(s) announced via the DSA-4619-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Guillaume Teissier reported that the XMLRPC client in libxmlrpc3-java,
an XML-RPC implementation in Java, does perform deserialization of the
server-side exception serialized in the faultCause attribute of XMLRPC
error response messages. A malicious XMLRPC server can take advantage of
this flaw to execute arbitrary code with the privileges of an
application using the Apache XMLRPC client library.

Note that a client that expects to get server-side exceptions need to
set explicitly the enabledForExceptions property.");

  script_tag(name:"affected", value:"'libxmlrpc3-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 3.1.3-8+deb9u1.

For the stable distribution (buster), this problem has been fixed in
version 3.1.3-9+deb10u1.

We recommend that you upgrade your libxmlrpc3-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-client-java", ver:"3.1.3-8+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-common-java", ver:"3.1.3-8+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-java-doc", ver:"3.1.3-8+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-server-java", ver:"3.1.3-8+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-client-java", ver:"3.1.3-9+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-common-java", ver:"3.1.3-9+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-java-doc", ver:"3.1.3-9+deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libxmlrpc3-server-java", ver:"3.1.3-9+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

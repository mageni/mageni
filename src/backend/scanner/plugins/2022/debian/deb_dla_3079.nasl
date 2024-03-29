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
  script_oid("1.3.6.1.4.1.25623.1.0.893079");
  script_version("2022-08-23T10:11:31+0000");
  script_cve_id("CVE-2022-2047", "CVE-2022-2048");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-08-23 10:11:31 +0000 (Tue, 23 Aug 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-15 15:35:00 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-08-22 01:00:09 +0000 (Mon, 22 Aug 2022)");
  script_name("Debian LTS: Security Advisory for jetty9 (DLA-3079-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/08/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3079-1");
  script_xref(name:"Advisory-ID", value:"DLA-3079-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jetty9'
  package(s) announced via the DLA-3079-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Two security vulnerabilities were discovered in Jetty, a Java servlet engine
and webserver.

CVE-2022-2047

In Eclipse Jetty the parsing of the authority segment of an http scheme
URI, the Jetty HttpURI class improperly detects an invalid input as a
hostname. This can lead to failures in a Proxy scenario.

CVE-2022-2048

In Eclipse Jetty HTTP/2 server implementation, when encountering an invalid
HTTP/2 request, the error handling has a bug that can wind up not properly
cleaning up the active connections and associated resources. This can lead
to a Denial of Service scenario where there are no enough resources left to
process good requests.");

  script_tag(name:"affected", value:"'jetty9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
9.4.16-0+deb10u2.

We recommend that you upgrade your jetty9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"jetty9", ver:"9.4.16-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjetty9-extra-java", ver:"9.4.16-0+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libjetty9-java", ver:"9.4.16-0+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

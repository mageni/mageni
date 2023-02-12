# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893279");
  script_version("2023-01-24T10:12:05+0000");
  script_cve_id("CVE-2021-37150", "CVE-2022-25763", "CVE-2022-28129", "CVE-2022-31780");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-24 10:12:05 +0000 (Tue, 24 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-24 02:00:06 +0000 (Tue, 24 Jan 2023)");
  script_name("Debian LTS: Security Advisory for trafficserver (DLA-3279-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00019.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3279-1");
  script_xref(name:"Advisory-ID", value:"DLA-3279-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'trafficserver'
  package(s) announced via the DLA-3279-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were found in trafficserver, a caching proxy
server.

CVE-2021-37150

Improper Input Validation vulnerability in header parsing of
Apache Traffic Server allows an attacker to request secure
resources

CVE-2022-25763

Improper Input Validation vulnerability in HTTP/2 request
validation of Apache Traffic Server allows an attacker to create
smuggle or cache poison attacks.

CVE-2022-28129

Improper Input Validation vulnerability in HTTP/1.1 header parsing
of Apache Traffic Server allows an attacker to send invalid
headers

CVE-2022-31780

Improper Input Validation vulnerability in HTTP/2 frame handling
of Apache Traffic Server allows an attacker to smuggle requests.");

  script_tag(name:"affected", value:"'trafficserver' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
8.0.2+ds-1+deb10u7.

We recommend that you upgrade your trafficserver packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"trafficserver", ver:"8.0.2+ds-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"trafficserver-dev", ver:"8.0.2+ds-1+deb10u7", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"trafficserver-experimental-plugins", ver:"8.0.2+ds-1+deb10u7", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

# Copyright (C) 2019 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.891858");
  script_version("2019-07-21T02:00:14+0000");
  script_cve_id("CVE-2019-12525", "CVE-2019-12529");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-21 02:00:14 +0000 (Sun, 21 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-21 02:00:14 +0000 (Sun, 21 Jul 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1858-1] squid3 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00018.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1858-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3'
  package(s) announced via the DSA-1858-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Squid, a high-performance proxy caching server for web clients, has been
found vulnerable to denial of service attacks associated with HTTP
authentication header processing.

CVE-2019-12525

Due to incorrect buffer management Squid is vulnerable to a denial
of service attack when processing HTTP Digest Authentication
credentials.

Due to incorrect input validation the HTTP Request header parser for
Digest authentication may access memory outside the allocated memory
buffer.

On systems with memory access protections this can result in the
Squid process being terminated unexpectedly. Resulting in a denial
of service for all clients using the proxy.

CVE-2019-12529

Due to incorrect buffer management Squid is vulnerable to a denial
of service attack when processing HTTP Basic Authentication
credentials.

Due to incorrect string termination the Basic authentication
credentials decoder may access memory outside the decode buffer.

On systems with memory access protections this can result in the
Squid process being terminated unexpectedly. Resulting in a denial
of service for all clients using the proxy.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.4.8-6+deb8u8.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.4.8-6+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.4.8-6+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.4.8-6+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3-common", ver:"3.4.8-6+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.4.8-6+deb8u8", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.4.8-6+deb8u8", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
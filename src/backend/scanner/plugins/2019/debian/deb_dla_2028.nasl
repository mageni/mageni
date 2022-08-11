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
  script_oid("1.3.6.1.4.1.25623.1.0.892028");
  script_version("2019-12-11T03:00:37+0000");
  script_cve_id("CVE-2019-12526", "CVE-2019-18677", "CVE-2019-18678", "CVE-2019-18679");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-12-11 03:00:37 +0000 (Wed, 11 Dec 2019)");
  script_tag(name:"creation_date", value:"2019-12-11 03:00:37 +0000 (Wed, 11 Dec 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 2028-1] squid3 security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/12/msg00011.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2028-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3'
  package(s) announced via the DSA-2028-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that Squid, a high-performance proxy caching server for
web clients, has been affected by the following security
vulnerabilities.

CVE-2019-12526

URN response handling in Squid suffers from a heap-based buffer
overflow. When receiving data from a remote server in response to
an URN request, Squid fails to ensure that the response can fit
within the buffer. This leads to attacker controlled data
overflowing in the heap.

CVE-2019-18677

When the append_domain setting is used (because the appended
characters do not properly interact with hostname length
restrictions), it can inappropriately redirect traffic to origins
it should not be delivered to. This happens because of incorrect
message processing.

CVE-2019-18678

A programming error allows attackers to smuggle HTTP requests
through frontend software to a Squid instance that splits the HTTP
Request pipeline differently. The resulting Response messages
corrupt caches (between a client and Squid) with
attacker-controlled content at arbitrary URLs. Effects are isolated
to software between the attacker client and Squid.
There are no effects on Squid itself, nor on any upstream servers.
The issue is related to a request header containing whitespace
between a header name and a colon.

CVE-2019-18679

Due to incorrect data management, Squid is vulnerable to
information disclosure when processing HTTP Digest Authentication.
Nonce tokens contain the raw byte value of a pointer that sits
within heap memory allocation. This information reduces ASLR
protections and may aid attackers isolating memory areas to target
for remote code execution attacks.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', these problems have been fixed in version
3.4.8-6+deb8u9.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.4.8-6+deb8u9", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.4.8-6+deb8u9", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.4.8-6+deb8u9", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3-common", ver:"3.4.8-6+deb8u9", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3-dbg", ver:"3.4.8-6+deb8u9", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.4.8-6+deb8u9", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
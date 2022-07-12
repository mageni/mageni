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
  script_oid("1.3.6.1.4.1.25623.1.0.892394");
  script_version("2020-10-05T08:44:07+0000");
  script_cve_id("CVE-2020-15049", "CVE-2020-15810", "CVE-2020-15811", "CVE-2020-24606");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_tag(name:"last_modification", value:"2020-10-05 09:55:30 +0000 (Mon, 05 Oct 2020)");
  script_tag(name:"creation_date", value:"2020-10-03 03:00:20 +0000 (Sat, 03 Oct 2020)");
  script_name("Debian LTS: Security Advisory for squid3 (DLA-2394-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2020/10/msg00005.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2394-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'squid3'
  package(s) announced via the DLA-2394-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in Squid, a high-
performance proxy caching server for web clients.

CVE-2020-15049

An issue was discovered in http/ContentLengthInterpreter.cc in
Squid. A Request Smuggling and Poisoning attack can succeed against
the HTTP cache. The client sends an HTTP request with a Content-
Length header containing '+\ '-' or an uncommon shell whitespace
character prefix to the length field-value.
This update also includes several other improvements to the
HttpHeader parsing code.

CVE-2020-15810 and CVE-2020-15811

Due to incorrect data validation, HTTP Request Smuggling attacks may
succeed against HTTP and HTTPS traffic. This leads to cache
poisoning and allows any client, including browser scripts, to
bypass local security and poison the proxy cache and any downstream
caches with content from an arbitrary source. When configured for
relaxed header parsing (the default), Squid relays headers
containing whitespace characters to upstream servers. When this
occurs as a prefix to a Content-Length header, the frame length
specified will be ignored by Squid (allowing for a conflicting
length to be used from another Content-Length header) but relayed
upstream.

CVE-2020-24606

Squid allows a trusted peer to perform Denial of Service by
consuming all available CPU cycles during handling of a crafted
Cache Digest response message. This only occurs when cache_peer is
used with the cache digests feature. The problem exists because
peerDigestHandleReply() livelocking in peer_digest.cc mishandles
EOF.");

  script_tag(name:"affected", value:"'squid3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
3.5.23-5+deb9u5.

We recommend that you upgrade your squid3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"squid", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-cgi", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-common", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-dbg", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid-purge", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squid3", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"squidclient", ver:"3.5.23-5+deb9u5", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

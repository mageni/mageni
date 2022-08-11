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
  script_oid("1.3.6.1.4.1.25623.1.0.892780");
  script_version("2021-10-14T08:01:30+0000");
  script_cve_id("CVE-2021-31799", "CVE-2021-31810", "CVE-2021-32066");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_tag(name:"last_modification", value:"2021-10-14 10:10:07 +0000 (Thu, 14 Oct 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-08-10 13:03:00 +0000 (Tue, 10 Aug 2021)");
  script_tag(name:"creation_date", value:"2021-10-14 01:00:08 +0000 (Thu, 14 Oct 2021)");
  script_name("Debian LTS: Security Advisory for ruby2.3 (DLA-2780-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/10/msg00009.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2780-1");
  script_xref(name:"Advisory-ID", value:"DLA-2780-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/990815");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.3'
  package(s) announced via the DLA-2780-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities in ruby2.3, interpreter of object-oriented
scripting language Ruby, were discovered.

CVE-2021-31799

In RDoc 3.11 through 6.x before 6.3.1, as distributed with
Ruby through 2.3.3, it is possible to execute arbitrary
code via a pipe char and tags in a filename.

CVE-2021-31810

An issue was discovered in Ruby through 2.3.3. A malicious
FTP server can use the PASV response to trick Net::FTP into
connecting back to a given IP address and port. This
potentially makes curl extract information about services
that are otherwise private and not disclosed (e.g., the
attacker can conduct port scans and service banner extractions).

CVE-2021-32066

An issue was discovered in Ruby through 2.3.3. Net::IMAP does
not raise an exception when StartTLS fails with an unknown
response, which might allow man-in-the-middle attackers to
bypass the TLS protections by leveraging a network position
between the client and the registry to block the StartTLS
command, aka a 'StartTLS stripping attack.'");

  script_tag(name:"affected", value:"'ruby2.3' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.3.3-1+deb9u10.

We recommend that you upgrade your ruby2.3 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libruby2.3", ver:"2.3.3-1+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.3", ver:"2.3.3-1+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-dev", ver:"2.3.3-1+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-doc", ver:"2.3.3-1+deb9u10", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.3-tcltk", ver:"2.3.3-1+deb9u10", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

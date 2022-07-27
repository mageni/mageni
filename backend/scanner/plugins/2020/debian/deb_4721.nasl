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
  script_oid("1.3.6.1.4.1.25623.1.0.704721");
  script_version("2020-07-09T03:00:06+0000");
  script_cve_id("CVE-2020-10663", "CVE-2020-10933");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2020-07-09 12:35:18 +0000 (Thu, 09 Jul 2020)");
  script_tag(name:"creation_date", value:"2020-07-09 03:00:06 +0000 (Thu, 09 Jul 2020)");
  script_name("Debian: Security Advisory for ruby2.5 (DSA-4721-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://www.debian.org/security/2020/dsa-4721.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4721-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby2.5'
  package(s) announced via the DSA-4721-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in the interpreter for the
Ruby language.

CVE-2020-10663
Jeremy Evans reported an unsafe object creation vulnerability in the
json gem bundled with Ruby. When parsing certain JSON documents, the
json gem can be coerced into creating arbitrary objects in the
target system.

CVE-2020-10933
Samuel Williams reported a flaw in the socket library which may lead
to exposure of possibly sensitive data from the interpreter.");

  script_tag(name:"affected", value:"'ruby2.5' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (buster), these problems have been fixed in
version 2.5.5-3+deb10u2.

We recommend that you upgrade your ruby2.5 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libruby2.5", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.5", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-dev", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"ruby2.5-doc", ver:"2.5.5-3+deb10u2", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

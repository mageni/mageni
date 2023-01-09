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
  script_oid("1.3.6.1.4.1.25623.1.0.893247");
  script_version("2022-12-29T11:40:20+0000");
  script_cve_id("CVE-2021-33623");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-12-29 11:40:20 +0000 (Thu, 29 Dec 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-07-02 12:15:00 +0000 (Fri, 02 Jul 2021)");
  script_tag(name:"creation_date", value:"2022-12-24 02:00:08 +0000 (Sat, 24 Dec 2022)");
  script_name("Debian LTS: Security Advisory for node-trim-newlines (DLA-3247-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/12/msg00033.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3247-1");
  script_xref(name:"Advisory-ID", value:"DLA-3247-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'node-trim-newlines'
  package(s) announced via the DLA-3247-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential remote denial of service
vulnerability in node-trim-newlines, a Javascript module to strip
newlines from the start and/or end of a string.

This regular expression Denial of Service (ReDoS) attack exploited
the fact that most Regular Expression implementations can reach
extreme situations that cause them to work very slowly in a way that
is exponentially related to the input size. An attacker can then
cause a program using node-trim-newlines (and thus the offending
regex) to enter one of these extreme situations and then hang for a
very long time.");

  script_tag(name:"affected", value:"'node-trim-newlines' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, this problem has been fixed in version
1.0.0-1+deb10u1.

We recommend that you upgrade your node-trim-newlines packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"node-trim-newlines", ver:"1.0.0-1+deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

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
  script_oid("1.3.6.1.4.1.25623.1.0.892852");
  script_version("2021-12-29T03:03:21+0000");
  script_cve_id("CVE-2020-9488", "CVE-2021-45105");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2021-12-29 11:11:49 +0000 (Wed, 29 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-21 06:15:00 +0000 (Tue, 21 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-27 02:00:29 +0000 (Mon, 27 Dec 2021)");
  script_name("Debian LTS: Security Advisory for apache-log4j2 (DLA-2852-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2021/12/msg00017.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2852-1");
  script_xref(name:"Advisory-ID", value:"DLA-2852-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/959450");
  script_xref(name:"URL", value:"https://bugs.debian.org/1001891");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-log4j2'
  package(s) announced via the DLA-2852-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities were found in Apache Log4j2, a Logging
Framework for Java, which could lead to a denial of service or information
disclosure.

CVE-2020-9488

Improper validation of certificate with host mismatch in Apache Log4j SMTP
appender. This could allow an SMTPS connection to be intercepted by a
man-in-the-middle attack which could leak any log messages sent through
that appender.

CVE-2021-45105

Apache Log4j2 did not protect from uncontrolled recursion from
self-referential lookups. This allows an attacker with control over Thread
Context Map data to cause a denial of service when a crafted string is
interpreted.");

  script_tag(name:"affected", value:"'apache-log4j2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
2.12.3-0+deb9u1.

We recommend that you upgrade your apache-log4j2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"liblog4j2-java", ver:"2.12.3-0+deb9u1", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblog4j2-java-doc", ver:"2.12.3-0+deb9u1", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

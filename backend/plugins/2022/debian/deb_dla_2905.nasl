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
  script_oid("1.3.6.1.4.1.25623.1.0.892905");
  script_version("2022-02-01T02:00:08+0000");
  script_cve_id("CVE-2021-4104", "CVE-2022-23302", "CVE-2022-23305", "CVE-2022-23307");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2022-02-01 11:05:08 +0000 (Tue, 01 Feb 2022)");
  script_tag(name:"creation_date", value:"2022-02-01 02:00:08 +0000 (Tue, 01 Feb 2022)");
  script_name("Debian LTS: Security Advisory for apache-log4j1.2 (DLA-2905-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB9");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2022/01/msg00033.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-2905-1");
  script_xref(name:"Advisory-ID", value:"DLA-2905-1");
  script_xref(name:"URL", value:"https://bugs.debian.org/1004482");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-log4j1.2'
  package(s) announced via the DLA-2905-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security vulnerabilities have been discovered in Apache Log4j 1.2, a
Java logging framework, when it is configured to use JMSSink, JDBCAppender,
JMSAppender or Apache Chainsaw which could be exploited for remote code
execution.

Note that a possible attacker requires write access to the Log4j configuration
and the aforementioned features are not enabled by default. In order to
completely mitigate against these type of vulnerabilities the related classes
have been removed from the resulting jar file.");

  script_tag(name:"affected", value:"'apache-log4j1.2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 9 stretch, these problems have been fixed in version
1.2.17-7+deb9u2.

We recommend that you upgrade your apache-log4j1.2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"liblog4j1.2-java", ver:"1.2.17-7+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblog4j1.2-java-doc", ver:"1.2.17-7+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

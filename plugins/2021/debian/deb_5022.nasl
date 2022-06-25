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
  script_oid("1.3.6.1.4.1.25623.1.0.705022");
  script_version("2021-12-17T14:03:21+0000");
  script_cve_id("CVE-2021-44228", "CVE-2021-45046");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-12-17 14:03:21 +0000 (Fri, 17 Dec 2021)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-12-14 01:15:00 +0000 (Tue, 14 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-17 02:00:33 +0000 (Fri, 17 Dec 2021)");
  script_name("Debian: Security Advisory for apache-log4j2 (DSA-5022-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|10)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5022.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5022-1");
  script_xref(name:"Advisory-ID", value:"DSA-5022-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-log4j2'
  package(s) announced via the DSA-5022-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was found that the fix to address CVE-2021-44228 
in Apache Log4j, a Logging Framework for Java, was
incomplete in certain non-default configurations. This could allow
attackers with control over Thread Context Map (MDC) input data when
the logging configuration uses a non-default Pattern Layout with
either a Context Lookup (for example, $${ctx:loginId}) or a Thread
Context Map pattern (%X, %mdc, or %MDC) to craft malicious input data
using a JNDI Lookup pattern resulting in a denial of service (DOS)
attack.");

  script_tag(name:"affected", value:"'apache-log4j2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), this problem has been fixed
in version 2.16.0-1~deb10u1.

For the stable distribution (bullseye), this problem has been fixed in
version 2.16.0-1~deb11u1.

We recommend that you upgrade your apache-log4j2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"liblog4j2-java", ver:"2.16.0-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblog4j2-java", ver:"2.16.0-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

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
  script_oid("1.3.6.1.4.1.25623.1.0.705020");
  script_version("2021-12-12T10:58:29+0000");
  script_cve_id("CVE-2020-9488", "CVE-2021-44228");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"2021-12-12 10:58:29 +0000 (Sun, 12 Dec 2021)");
  script_tag(name:"creation_date", value:"2021-12-12 10:58:29 +0000 (Sun, 12 Dec 2021)");
  script_name("Debian: Security Advisory for apache-log4j2 (DSA-5020-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2021 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|11)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2021/dsa-5020.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5020-1");
  script_xref(name:"Advisory-ID", value:"DSA-5020-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'apache-log4j2'
  package(s) announced via the DSA-5020-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chen Zhaojun of Alibaba Cloud Security Team discovered a critical security
vulnerability in Apache Log4j, a popular Logging Framework for Java. JNDI
features used in configuration, log messages, and parameters do not protect
against attacker controlled LDAP and other JNDI related endpoints. An attacker
who can control log messages or log message parameters can execute arbitrary
code loaded from LDAP servers when message lookup substitution is enabled. From
version 2.15.0, this behavior has been disabled by default.

This update also fixes CVE-2020-9488
in the oldstable distribution (buster). Improper validation
of certificate with host mismatch in Apache Log4j SMTP appender. This could
allow an SMTPS connection to be intercepted by a man-in-the-middle attack
which could leak any log messages sent through that appender.");

  script_tag(name:"affected", value:"'apache-log4j2' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (buster), this problem has been fixed
in version 2.15.0-1~deb10u1.

For the stable distribution (bullseye), this problem has been fixed in
version 2.15.0-1~deb11u1.

We recommend that you upgrade your apache-log4j2 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"liblog4j2-java", ver:"2.15.0-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"liblog4j2-java", ver:"2.15.0-1~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

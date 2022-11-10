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
  script_oid("1.3.6.1.4.1.25623.1.0.705265");
  script_version("2022-11-09T08:42:14+0000");
  script_cve_id("CVE-2020-9484", "CVE-2021-43980", "CVE-2022-23181", "CVE-2022-29885");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2022-11-09 08:42:14 +0000 (Wed, 09 Nov 2022)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-20 18:03:00 +0000 (Fri, 20 May 2022)");
  script_tag(name:"creation_date", value:"2022-10-31 02:00:15 +0000 (Mon, 31 Oct 2022)");
  script_name("Debian: Security Advisory for tomcat9 (DSA-5265-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5265.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5265-1");
  script_xref(name:"Advisory-ID", value:"DSA-5265-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'tomcat9'
  package(s) announced via the DSA-5265-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in the Tomcat
servlet and JSP engine.

CVE-2021-43980
The simplified implementation of blocking reads and writes introduced in
Tomcat 10 and back-ported to Tomcat 9.0.47 onwards exposed a long standing
(but extremely hard to trigger) concurrency bug that could cause client
connections to share an Http11Processor instance resulting in responses, or
part responses, to be received by the wrong client.

CVE-2022-23181The fix for bug CVE-2020-9484
introduced a time of check, time of use
vulnerability into Apache Tomcat that allowed a local attacker to perform
actions with the privileges of the user that the Tomcat process is using.
This issue is only exploitable when Tomcat is configured to persist
sessions using the FileStore.

CVE-2022-29885
The documentation of Apache Tomcat for the EncryptInterceptor incorrectly
stated it enabled Tomcat clustering to run over an untrusted network. This
was not correct. While the EncryptInterceptor does provide confidentiality
and integrity protection, it does not protect against all risks associated
with running over any untrusted network, particularly DoS risks.");

  script_tag(name:"affected", value:"'tomcat9' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 9.0.43-2~deb11u4.

We recommend that you upgrade your tomcat9 packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-embed-java", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libtomcat9-java", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-admin", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-common", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-docs", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-examples", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"tomcat9-user", ver:"9.0.43-2~deb11u4", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

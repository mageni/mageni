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
  script_oid("1.3.6.1.4.1.25623.1.0.891848");
  script_version("2019-07-11T10:16:38+0000");
  script_cve_id("CVE-2019-11272");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-07-11 10:16:38 +0000 (Thu, 11 Jul 2019)");
  script_tag(name:"creation_date", value:"2019-07-10 02:00:06 +0000 (Wed, 10 Jul 2019)");
  script_name("Debian LTS Advisory ([SECURITY] [DLA 1848-1] libspring-security-2.0-java security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB8");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-1848-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libspring-security-2.0-java'
  package(s) announced via the DSA-1848-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Spring Security support plain text passwords using
PlaintextPasswordEncoder. If an application using an affected version
of Spring Security is leveraging PlaintextPasswordEncoder and a user
has a null encoded password, a malicious user (or attacker) can
authenticate using a password of 'null'.");

  script_tag(name:"affected", value:"'libspring-security-2.0-java' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 8 'Jessie', this problem has been fixed in version
2.0.7.RELEASE-3+deb8u2.

We recommend that you upgrade your libspring-security-2.0-java packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"libspring-security-2.0-java-doc", ver:"2.0.7.RELEASE-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-security-acl-2.0-java", ver:"2.0.7.RELEASE-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-security-core-2.0-java", ver:"2.0.7.RELEASE-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-security-ntlm-2.0-java", ver:"2.0.7.RELEASE-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-security-portlet-2.0-java", ver:"2.0.7.RELEASE-3+deb8u2", rls:"DEB8"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libspring-security-taglibs-2.0-java", ver:"2.0.7.RELEASE-3+deb8u2", rls:"DEB8"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
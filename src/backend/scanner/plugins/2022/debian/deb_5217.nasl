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
  script_oid("1.3.6.1.4.1.25623.1.0.705217");
  script_version("2022-08-26T01:00:10+0000");
  script_cve_id("CVE-2022-38472", "CVE-2022-38473", "CVE-2022-38478");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2022-08-26 01:00:10 +0000 (Fri, 26 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-26 01:00:10 +0000 (Fri, 26 Aug 2022)");
  script_name("Debian: Security Advisory for firefox-esr (DSA-5217-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"URL", value:"https://www.debian.org/security/2022/dsa-5217.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5217-1");
  script_xref(name:"Advisory-ID", value:"DSA-5217-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-esr'
  package(s) announced via the DSA-5217-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox
web browser, which could potentially result in the execution
of arbitrary code or spoofing.");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the stable distribution (bullseye), these problems have been fixed in
version 91.13.0esr-1~deb11u1.

We recommend that you upgrade your firefox-esr packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-be", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca-valencia", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cak", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-ca", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ia", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ka", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kab", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-my", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ne-np", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-oc", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sco", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-szl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tl", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-trs", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ur", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"91.13.0esr-1~deb11u1", rls:"DEB11"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

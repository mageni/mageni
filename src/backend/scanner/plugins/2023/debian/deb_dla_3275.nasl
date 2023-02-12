# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.893275");
  script_version("2023-01-20T10:11:50+0000");
  script_cve_id("CVE-2022-46871", "CVE-2022-46877", "CVE-2023-23598", "CVE-2023-23601", "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23605");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-01-20 10:11:50 +0000 (Fri, 20 Jan 2023)");
  script_tag(name:"creation_date", value:"2023-01-20 02:00:14 +0000 (Fri, 20 Jan 2023)");
  script_name("Debian LTS: Security Advisory for firefox-esr (DLA-3275-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"URL", value:"https://lists.debian.org/debian-lts-announce/2023/01/msg00015.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DLA-3275-1");
  script_xref(name:"Advisory-ID", value:"DLA-3275-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox-esr'
  package(s) announced via the DLA-3275-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues have been found in the Mozilla Firefox web
browser, which could potentially result in the execution of arbitrary
code, information disclosure or spoofing.");

  script_tag(name:"affected", value:"'firefox-esr' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For Debian 10 buster, these problems have been fixed in version
102.7.0esr-1~deb10u1.

We recommend that you upgrade your firefox-esr packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ach", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-af", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-all", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-an", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ar", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ast", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-az", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-be", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bg", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-br", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-bs", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ca-valencia", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cak", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cs", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-cy", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-da", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-de", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-dsb", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-el", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-ca", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-en-gb", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eo", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-ar", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-cl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-es", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-es-mx", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-et", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-eu", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fa", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ff", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fi", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-fy-nl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ga-ie", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gd", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-gu-in", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-he", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hi-in", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hsb", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hu", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-hy-am", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ia", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-id", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-is", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-it", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ja", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ka", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kab", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-km", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-kn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ko", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lij", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lt", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-lv", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-mr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ms", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-my", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nb-no", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ne-np", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-nn-no", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-oc", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pa-in", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-br", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-pt-pt", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-rm", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ro", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ru", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sco", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-si", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-son", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sq", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-sv-se", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-szl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ta", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-te", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-th", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-tr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-trs", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-ur", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-uz", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-vi", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-xh", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-cn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"firefox-esr-l10n-zh-tw", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ach", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-af", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-all", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-an", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ar", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ast", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-az", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-be", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bg", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-br", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-bs", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ca-valencia", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cak", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cs", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-cy", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-da", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-de", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-dsb", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-el", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-ca", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-en-gb", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eo", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-ar", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-cl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-es", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-es-mx", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-et", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-eu", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fa", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ff", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fi", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-fy-nl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ga-ie", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gd", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-gu-in", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-he", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hi-in", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hsb", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hu", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-hy-am", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ia", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-id", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-is", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-it", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ja", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ka", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kab", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-km", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-kn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ko", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lij", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lt", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-lv", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-mr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ms", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-my", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nb-no", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ne-np", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-nn-no", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-oc", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pa-in", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-br", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-pt-pt", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-rm", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ro", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ru", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sco", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-si", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-son", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sq", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-sv-se", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-szl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ta", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-te", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-th", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tl", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-tr", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-trs", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uk", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-ur", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-uz", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-vi", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-xh", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-cn", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"iceweasel-l10n-zh-tw", ver:"102.7.0esr-1~deb10u1", rls:"DEB10"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);

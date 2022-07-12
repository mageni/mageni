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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2016.308.01");
  script_cve_id("CVE-2016-8615", "CVE-2016-8616", "CVE-2016-8617", "CVE-2016-8618", "CVE-2016-8619", "CVE-2016-8620", "CVE-2016-8621", "CVE-2016-8622", "CVE-2016-8623", "CVE-2016-8624", "CVE-2016-8625");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-11-13 11:29:00 +0000 (Tue, 13 Nov 2018)");

  script_name("Slackware: Security Advisory (SSA:2016-308-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.0|13\.1|13\.37|14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2016-308-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2016&m=slackware-security.661139");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102A.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102B.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102C.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102D.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102E.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102F.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102G.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102H.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102I.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102J.html");
  script_xref(name:"URL", value:"https://curl.haxx.se/docs/adv_20161102K.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'curl' package(s) announced via the SSA:2016-308-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New curl packages are available for Slackware 13.0, 13.1, 13.37, 14.0, 14.1,
14.2, and -current to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/curl-7.51.0-i586-1_slack14.2.txz: Upgraded.
 This release fixes security issues:
 CVE-2016-8615: cookie injection for other servers
 CVE-2016-8616: case insensitive password comparison
 CVE-2016-8617: OOB write via unchecked multiplication
 CVE-2016-8618: double-free in curl_maprintf
 CVE-2016-8619: double-free in krb5 code
 CVE-2016-8620: glob parser write/read out of bounds
 CVE-2016-8621: curl_getdate read out of bounds
 CVE-2016-8622: URL unescape heap overflow via integer truncation
 CVE-2016-8623: Use-after-free via shared cookies
 CVE-2016-8624: invalid URL parsing with '#'
 CVE-2016-8625: IDNA 2003 makes curl use wrong host
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'curl' package(s) on Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"curl", ver:"7.51.0-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

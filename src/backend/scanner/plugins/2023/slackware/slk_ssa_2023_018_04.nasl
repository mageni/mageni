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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.018.04");
  script_cve_id("CVE-2022-46871", "CVE-2022-46877", "CVE-2023-23598", "CVE-2023-23599", "CVE-2023-23601", "CVE-2023-23602", "CVE-2023-23603", "CVE-2023-23605");
  script_tag(name:"creation_date", value:"2023-01-19 04:18:23 +0000 (Thu, 19 Jan 2023)");
  script_version("2023-01-19T10:10:48+0000");
  script_tag(name:"last_modification", value:"2023-01-19 10:10:48 +0000 (Thu, 19 Jan 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-01-04 18:40:00 +0000 (Wed, 04 Jan 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-018-04)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-018-04");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.389395");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-46871");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2022-46877");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23598");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23599");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23601");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23602");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23603");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-23605");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/firefox/102.7.0/releasenotes/");
  script_xref(name:"URL", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2023-02/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mozilla-firefox' package(s) announced via the SSA:2023-018-04 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New mozilla-firefox packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/mozilla-firefox-102.7.0esr-i686-1_slack15.0.txz: Upgraded.
 This update contains security fixes and improvements.
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
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'mozilla-firefox' package(s) on Slackware 15.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

release = slk_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "SLK15.0") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"102.7.0esr-i686-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"102.7.0esr-x86_64-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLKcurrent") {

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"109.0-i686-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"mozilla-firefox", ver:"109.0-x86_64-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

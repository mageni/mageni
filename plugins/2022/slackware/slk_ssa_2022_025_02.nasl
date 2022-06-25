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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.025.02");
  script_cve_id("CVE-2021-4034");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-01-31 17:50:00 +0000 (Mon, 31 Jan 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-025-02)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2022-025-02");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.434679");
  script_xref(name:"URL", value:"https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'polkit' package(s) announced via the SSA:2022-025-02 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New polkit packages are available for Slackware 14.0, 14.1, 14.2, and -current
to fix a security issue.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/polkit-0.113-i586-4_slack14.2.txz: Rebuilt.
 [PATCH] pkexec: local privilege escalation.
 Thanks to Qualys Research Labs for reporting this issue.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'polkit' package(s) on Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"polkit", ver:"0.105-i486-5_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"polkit", ver:"0.105-x86_64-5_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"polkit", ver:"0.105-i486-5_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"polkit", ver:"0.105-x86_64-5_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"polkit", ver:"0.113-i586-4_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"polkit", ver:"0.113-x86_64-4_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2023.090.01");
  script_cve_id("CVE-2023-28755", "CVE-2023-28756");
  script_tag(name:"creation_date", value:"2023-04-03 04:19:31 +0000 (Mon, 03 Apr 2023)");
  script_version("2023-04-10T10:08:59+0000");
  script_tag(name:"last_modification", value:"2023-04-10 10:08:59 +0000 (Mon, 10 Apr 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-07 17:25:00 +0000 (Fri, 07 Apr 2023)");

  script_name("Slackware: Security Advisory (SSA:2023-090-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(15\.0|current)");

  script_xref(name:"Advisory-ID", value:"SSA:2023-090-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2023&m=slackware-security.351755");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-28755");
  script_xref(name:"URL", value:"https://www.cve.org/CVERecord?id=CVE-2023-28756");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2023/03/28/redos-in-uri-cve-2023-28755/");
  script_xref(name:"URL", value:"https://www.ruby-lang.org/en/news/2023/03/30/redos-in-time-cve-2023-28756/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ruby' package(s) announced via the SSA:2023-090-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New ruby packages are available for Slackware 15.0 and -current to
fix security issues.


Here are the details from the Slackware 15.0 ChangeLog:
+--------------------------+
patches/packages/ruby-3.0.6-i586-1_slack15.0.txz: Upgraded.
 This update fixes security issues:
 ReDoS vulnerability in URI.
 ReDoS vulnerability in Time.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'ruby' package(s) on Slackware 15.0, Slackware current.");

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

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"3.0.6-i586-1_slack15.0", rls:"SLK15.0"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"3.0.6-x86_64-1_slack15.0", rls:"SLK15.0"))) {
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

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"3.2.2-i586-1", rls:"SLKcurrent"))) {
    report += res;
  }

  if(!isnull(res = isslkpkgvuln(pkg:"ruby", ver:"3.2.2-x86_64-1", rls:"SLKcurrent"))) {
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

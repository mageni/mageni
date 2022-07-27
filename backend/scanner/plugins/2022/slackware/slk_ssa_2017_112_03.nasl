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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2017.112.03");
  script_cve_id("CVE-2017-7418");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-08-08 15:15:00 +0000 (Thu, 08 Aug 2019)");

  script_name("Slackware: Security Advisory (SSA:2017-112-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(13\.0|13\.1|13\.37|14\.0|14\.1|14\.2)");

  script_xref(name:"Advisory-ID", value:"SSA:2017-112-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.545090");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'proftpd' package(s) announced via the SSA:2017-112-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New proftpd packages are available for Slackware 13.0, 13.1, 13.37, 14.0, 14.1,
14.2, and -current to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/proftpd-1.3.5e-i586-1_slack14.2.txz: Upgraded.
 This release fixes a security issue:
 AllowChrootSymlinks off does not check entire DefaultRoot path for symlinks.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'proftpd' package(s) on Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware 14.1, Slackware 14.2, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-i486-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-x86_64-1_slack14.1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-i586-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"proftpd", ver:"1.3.5e-x86_64-1_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

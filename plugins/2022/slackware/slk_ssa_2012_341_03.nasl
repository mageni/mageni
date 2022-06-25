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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2012.341.03");
  script_cve_id("CVE-2012-5134");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_name("Slackware: Security Advisory (SSA:2012-341-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.1|12\.2|13\.0|13\.1|13\.37|14\.0)");

  script_xref(name:"Advisory-ID", value:"SSA:2012-341-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2012&m=slackware-security.514209");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxml2' package(s) announced via the SSA:2012-341-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New libxml2 packages are available for Slackware 12.1, 12.2, 13.0, 13.1, 13.37,
14.0, and -current to fix a security issue.


Here are the details from the Slackware 14.0 ChangeLog:
+--------------------------+
patches/packages/libxml2-2.8.0-i486-2_slack14.0.txz: Rebuilt.
 Patched a heap-based buffer underflow in the xmlParseAttValueComplex
 function in parser.c in libxml2 2.9.0 and earlier that could allow a
 remote attacker to cause a denial of service or possibly execute
 arbitrary code via crafted entities in an XML document.
 For more information, see:
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'libxml2' package(s) on Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.6.32-i486-3_slack12.1", rls:"SLK12.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.6.32-i486-4_slack12.2", rls:"SLK12.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.7.3-i486-5_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.7.3-x86_64-5_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.7.6-i486-3_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.7.6-x86_64-3_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.7.8-i486-5_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.7.8-x86_64-5_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.8.0-i486-2_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"libxml2", ver:"2.8.0-x86_64-2_slack14.0", rls:"SLK14.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

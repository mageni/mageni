# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2011_224_01.nasl 14202 2019-03-15 09:16:15Z cfischer $
# Description: Auto-generated from advisory SSA:2011-224-01
#
# Authors:
# Thomas Reinke <reinke@securityspace.com>
#
# Copyright:
# Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2,
# or at your option, GNU General Public License version 3,
# as published by the Free Software Foundation
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.71963");
  script_cve_id("CVE-2011-1910", "CVE-2011-2464");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_version("$Revision: 14202 $");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $");
  script_tag(name:"creation_date", value:"2012-09-10 07:16:18 -0400 (Mon, 10 Sep 2012)");
  script_name("Slackware Advisory SSA:2011-224-01 bind");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0|9\.1|10\.0|10\.1|10\.2|11\.0|12\.0|12\.1|12\.2|13\.0|13\.1|13\.37)");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2011-224-01");

  script_tag(name:"insight", value:"New bind packages are available for Slackware 8.1, 9.0, 9.1, 10.0, 10.1, 10.2,
11.0, 12.0, 12.1, 12.2, 13.0, 13.1, 13.37, and -current to fix security issues.");

  script_tag(name:"solution", value:"Upgrade to the new package(s).");

  script_tag(name:"summary", value:"The remote host is missing an update as announced
via advisory SSA:2011-224-01.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

report = "";
res = "";

if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i386-1_slack8.1", rls:"SLK8.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i386-1_slack9.0", rls:"SLK9.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack9.1", rls:"SLK9.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack10.0", rls:"SLK10.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack10.1", rls:"SLK10.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack10.2", rls:"SLK10.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack11.0", rls:"SLK11.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack12.0", rls:"SLK12.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack12.1", rls:"SLK12.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack12.2", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack13.0", rls:"SLK13.0")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.4_ESV_R5-i486-1_slack13.1", rls:"SLK13.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"bind", ver:"9.7.4-i486-1_slack13.37", rls:"SLK13.37")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
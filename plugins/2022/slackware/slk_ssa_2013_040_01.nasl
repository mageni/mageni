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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2013.040.01");
  script_cve_id("CVE-2012-2686", "CVE-2013-0166", "CVE-2013-0169");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_name("Slackware: Security Advisory (SSA:2013-040-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.1|12\.2|13\.0|13\.1|13\.37|14\.0)");

  script_xref(name:"Advisory-ID", value:"SSA:2013-040-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2013&m=slackware-security.839296");
  script_xref(name:"URL", value:"http://www.isg.rhul.ac.uk/tls/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2013-040-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 12.1, 12.2, 13.0, 13.1, 13.37,
14.0, and -current to fix security issues.


Here are the details from the Slackware 14.0 ChangeLog:
+--------------------------+
patches/packages/openssl-1.0.1d-i486-1_slack14.0.txz: Upgraded.
 Make the decoding of SSLv3, TLS and DTLS CBC records constant time.
 This addresses the flaw in CBC record processing discovered by
 Nadhem Alfardan and Kenny Paterson. Details of this attack can be found
 at: [link moved to references]
 Thanks go to Nadhem Alfardan and Kenny Paterson of the Information
 Security Group at Royal Holloway, University of London
 (www.isg.rhul.ac.uk) for discovering this flaw and Adam Langley and
 Emilia Kasper for the initial patch.
 (CVE-2013-0169)
 [Emilia Kasper, Adam Langley, Ben Laurie, Andy Polyakov, Steve Henson]
 Fix flaw in AESNI handling of TLS 1.2 and 1.1 records for CBC mode
 ciphersuites which can be exploited in a denial of service attack.
 Thanks go to and to Adam Langley <agl@chromium.org> for discovering
 and detecting this bug and to Wolfgang Ettlinger
 <wolfgang.ettlinger@gmail.com> for independently discovering this issue.
 (CVE-2012-2686)
 [Adam Langley]
 Return an error when checking OCSP signatures when key is NULL.
 This fixes a DoS attack. (CVE-2013-0166)
 [Steve Henson]
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/openssl-solibs-1.0.1d-i486-1_slack14.0.txz: Upgraded.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'openssl' package(s) on Slackware 12.1, Slackware 12.2, Slackware 13.0, Slackware 13.1, Slackware 13.37, Slackware 14.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-i486-1_slack12.1", rls:"SLK12.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-i486-1_slack12.1", rls:"SLK12.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-i486-1_slack12.2", rls:"SLK12.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-i486-1_slack12.2", rls:"SLK12.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-i486-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-x86_64-1_slack13.0", rls:"SLK13.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-i486-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-x86_64-1_slack13.1", rls:"SLK13.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"0.9.8y-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-i486-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"0.9.8y-x86_64-1_slack13.37", rls:"SLK13.37"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.0.1d-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.0.1d-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.0.1d-i486-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.0.1d-x86_64-1_slack14.0", rls:"SLK14.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

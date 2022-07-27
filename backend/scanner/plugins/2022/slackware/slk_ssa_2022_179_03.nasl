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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.179.03");
  script_cve_id("CVE-2022-1292", "CVE-2022-2068");
  script_tag(name:"creation_date", value:"2022-06-29 04:50:21 +0000 (Wed, 29 Jun 2022)");
  script_version("2022-07-13T10:13:19+0000");
  script_tag(name:"last_modification", value:"2022-07-13 10:13:19 +0000 (Wed, 13 Jul 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 15:15:00 +0000 (Thu, 07 Jul 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-179-03)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2022-179-03");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.411358");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20220621.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the SSA:2022-179-03 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New openssl packages are available for Slackware 14.2 to fix a security issue.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/openssl-1.0.2u-i586-4_slack14.2.txz: Rebuilt.
 We're sending out the Slackware 14.2 updates again because the package
 build number wasn't incremented which caused slackpkg to not pick up the
 updates. It's been bumped and the packages rebuilt - otherwise there are
 no new changes. Thanks to John Jenkins for the report.
 For reference, here's the information from the previous advisory:
 In addition to the c_rehash shell command injection identified in
 CVE-2022-1292, further circumstances where the c_rehash script does not
 properly sanitise shell metacharacters to prevent command injection were
 found by code review.
 When the CVE-2022-1292 was fixed it was not discovered that there
 are other places in the script where the file names of certificates
 being hashed were possibly passed to a command executed through the shell.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/openssl-solibs-1.0.2u-i586-4_slack14.2.txz: Rebuilt.
+--------------------------+");

  script_tag(name:"affected", value:"'openssl' package(s) on Slackware 14.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.0.2u-i586-4_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl", ver:"1.0.2u-x86_64-4_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.0.2u-i586-4_slack14.2", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"openssl-solibs", ver:"1.0.2u-x86_64-4_slack14.2", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

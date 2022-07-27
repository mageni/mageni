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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2003.195.01");
  script_cve_id("CVE-2003-0252");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-09T10:02:45+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_name("Slackware: Security Advisory (SSA:2003-195-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(8\.1|9\.0)");

  script_xref(name:"Advisory-ID", value:"SSA:2003-195-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2003&m=slackware-security.374504");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nfs-utils' package(s) announced via the SSA:2003-195-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New nfs-utils packages are available for Slackware 8.1, 9.0, and -current
to fix an off-by-one buffer overflow in xlog.c. Thanks to Janusz
Niewiadomski for discovering and reporting this problem.

The CVE (Common Vulnerabilities and Exposures) Project has assigned the
identification number CAN-2003-0252 to this issue.

Here are the details from the Slackware 9.0 ChangeLog:
+--------------------------+
iMon Jul 14 14:15:34 PDT 2003
patches/packages/nfs-utils-1.0.4-i386-1.tgz: Upgraded to nfs-utils-1.0.4.
 This fixes an off-by-one buffer overflow in xlog.c which could be used
 by an attacker to produce a denial of NFS service, or to execute
 arbitrary code. All sites providing NFS services should upgrade to
 this new package immediately.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'nfs-utils' package(s) on Slackware 8.1, Slackware 9.0, Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"nfs-utils", ver:"1.0.4-i386-1", rls:"SLK8.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"nfs-utils", ver:"1.0.4-i386-1", rls:"SLK9.0"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

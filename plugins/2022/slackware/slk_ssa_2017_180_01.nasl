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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2017.180.01");
  script_cve_id("CVE-2017-1000364", "CVE-2017-1000365");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)");

  script_name("Slackware: Security Advisory (SSA:2017-180-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.1");

  script_xref(name:"Advisory-ID", value:"SSA:2017-180-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2017&m=slackware-security.696048");
  script_xref(name:"URL", value:"https://www.qualys.com/2017/06/19/stack-clash/stack-clash.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2017-180-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 14.1 to fix security issues.


Here are the details from the Slackware 14.1 ChangeLog:
+--------------------------+
patches/packages/linux-3.10.107/*: Upgraded.
 This kernel fixes two 'Stack Clash' vulnerabilities reported by Qualys.
 The first issue may allow attackers to execute arbitrary code with elevated
 privileges. Failed attack attempts will likely result in denial-of-service
 conditions. The second issue can be exploited to bypass certain security
 restrictions and perform unauthorized actions.
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
 In addition, a patch is included and preapplied to guard against other == sk
 in unix_dgram_sendmsg. This bug has been known to cause Samba related stalls.
 Thanks to Ben Stern for the bug report.
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 14.1.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"3.10.107-i486-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"3.10.107-x86_64-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"3.10.107_smp-i686-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"3.10.107-x86-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"3.10.107_smp-x86-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"3.10.107-i486-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"3.10.107-x86_64-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"3.10.107_smp-i686-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"3.10.107-i486-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"3.10.107-x86_64-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"3.10.107_smp-i686-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"3.10.107-noarch-1", rls:"SLK14.1"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"3.10.107_smp-noarch-1", rls:"SLK14.1"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

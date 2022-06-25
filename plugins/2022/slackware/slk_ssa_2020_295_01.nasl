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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2020.295.01");
  script_cve_id("CVE-2018-10323", "CVE-2018-13094", "CVE-2018-8043", "CVE-2019-19054", "CVE-2019-19073", "CVE-2019-19074", "CVE-2019-19448", "CVE-2019-20810", "CVE-2019-9445", "CVE-2020-12351", "CVE-2020-12352", "CVE-2020-12771", "CVE-2020-14314", "CVE-2020-14331", "CVE-2020-14390", "CVE-2020-15393", "CVE-2020-16166", "CVE-2020-24490", "CVE-2020-25211", "CVE-2020-25212", "CVE-2020-25284", "CVE-2020-25285", "CVE-2020-25643", "CVE-2020-26088");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)");

  script_name("Slackware: Security Advisory (SSA:2020-295-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2020-295-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2020&m=slackware-security.780685");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2020-295-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 14.2 to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/linux-4.4.240/*: Upgraded.
 These updates fix various bugs and security issues, including the recently
 discovered 'Bleeding Tooth' vulnerability in the Bluetooth subsystem
 (CVE-2020-12351, CVE-2020-12352, and CVE-2020-24490).
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 Fixed in 4.4.228:
 [link moved to references]
 Fixed in 4.4.229:
 [link moved to references]
 Fixed in 4.4.230:
 [link moved to references]
 Fixed in 4.4.232:
 [link moved to references]
 Fixed in 4.4.233:
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
 [link moved to references]
 Fixed in 4.4.234:
 [link moved to references]
 Fixed in 4.4.236:
 [link moved to references]
 Fixed in 4.4.237:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.238:
 [link moved to references]
 Fixed in 4.4.239:
 [link moved to references]
 Fixed in 4.4.240:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware 14.2.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.240-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.240-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"4.4.240_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.240-x86-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.240_smp-x86-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.240-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.240-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"4.4.240_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.240-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.240-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"4.4.240_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.240-noarch-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.240_smp-noarch-1", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

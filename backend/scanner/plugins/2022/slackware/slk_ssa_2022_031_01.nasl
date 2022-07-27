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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2022.031.01");
  script_cve_id("CVE-2020-29374", "CVE-2020-3702", "CVE-2021-0920", "CVE-2021-20320", "CVE-2021-20321", "CVE-2021-21781", "CVE-2021-28711", "CVE-2021-28712", "CVE-2021-28713", "CVE-2021-28715", "CVE-2021-3640", "CVE-2021-3653", "CVE-2021-3655", "CVE-2021-3679", "CVE-2021-37159", "CVE-2021-3732", "CVE-2021-3752", "CVE-2021-3753", "CVE-2021-37576", "CVE-2021-3760", "CVE-2021-3772", "CVE-2021-38204", "CVE-2021-38205", "CVE-2021-3896", "CVE-2021-39685", "CVE-2021-4002", "CVE-2021-40490", "CVE-2021-4083", "CVE-2021-4155", "CVE-2021-42008", "CVE-2021-4202", "CVE-2021-4203", "CVE-2021-43389", "CVE-2021-43976", "CVE-2021-45095", "CVE-2022-0330");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.9");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-28 19:47:00 +0000 (Mon, 28 Feb 2022)");

  script_name("Slackware: Security Advisory (SSA:2022-031-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2022-031-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2022&m=slackware-security.852695");
  script_xref(name:"URL", value:"https://seclists.org/oss-sec/2022/q1/81");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2022-031-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 14.2 to fix security issues.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
patches/packages/linux-4.4.301/*: Upgraded.
 These updates fix various bugs and security issues, including the recently
 announced i915 issue that could lead to user-space gaining access to random
 memory pages (CVE-2022-0330).
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 [link moved to references]
 Fixed in 4.4.277:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.278:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.281:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.282:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.283:
 [link moved to references]
 Fixed in 4.4.284:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.285:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.288:
 [link moved to references]
 Fixed in 4.4.289:
 [link moved to references]
 Fixed in 4.4.290:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.291:
 [link moved to references]
 Fixed in 4.4.292:
 [link moved to references]
 Fixed in 4.4.293:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.294:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.295:
 [link moved to references]
 Fixed in 4.4.296:
 [link moved to references]
 ... [Please see the references for more information on the vulnerabilities]");

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

if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.301-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.301-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"4.4.301_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.301-x86-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.301_smp-x86-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.301-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.301-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"4.4.301_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.301-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.301-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"4.4.301_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.301-noarch-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.301_smp-noarch-1", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

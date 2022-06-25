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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2021.202.01");
  script_cve_id("CVE-2017-0605", "CVE-2019-16232", "CVE-2019-19060", "CVE-2019-19061", "CVE-2020-24586", "CVE-2020-24587", "CVE-2020-24588", "CVE-2020-25670", "CVE-2020-25671", "CVE-2020-25672", "CVE-2020-25673", "CVE-2020-26139", "CVE-2020-26147", "CVE-2020-26558", "CVE-2021-0129", "CVE-2021-20261", "CVE-2021-22555", "CVE-2021-28660", "CVE-2021-28688", "CVE-2021-28964", "CVE-2021-28972", "CVE-2021-29154", "CVE-2021-29265", "CVE-2021-29650", "CVE-2021-31916", "CVE-2021-32399", "CVE-2021-33034", "CVE-2021-33909", "CVE-2021-34693", "CVE-2021-3483", "CVE-2021-3564", "CVE-2021-3573", "CVE-2021-3587");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-10 10:06:01 +0000 (Tue, 10 May 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-29 10:15:00 +0000 (Tue, 29 Jun 2021)");

  script_name("Slackware: Security Advisory (SSA:2021-202-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK14\.2");

  script_xref(name:"Advisory-ID", value:"SSA:2021-202-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2021&m=slackware-security.837633");
  script_xref(name:"URL", value:"https://www.qualys.com/2021/07/20/cve-2021-33909/sequoia-local-privilege-escalation-linux.txt");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2021-202-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware 14.2 to fix a security issue.


Here are the details from the Slackware 14.2 ChangeLog:
+--------------------------+
Wed Jul 21 05:30:44 UTC 2021
patches/packages/linux-4.4.276/*: Upgraded.
 These updates fix various bugs and security issues, including the recently
 announced local privilege escalation vulnerability in the filesystem layer
 (CVE-2021-33909).
 Be sure to upgrade your initrd after upgrading the kernel packages.
 If you use lilo to boot your machine, be sure lilo.conf points to the correct
 kernel and initrd and run lilo as root to update the bootloader.
 If you use elilo to boot your machine, you should run eliloconfig to copy the
 kernel and initrd to the EFI System Partition.
 For more information, see:
 [link moved to references]
 Fixed in 4.4.262:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.263:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.264:
 [link moved to references]
 Fixed in 4.4.265:
 [link moved to references]
 Fixed in 4.4.266:
 [link moved to references]
 Fixed in 4.4.267:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.269:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.270:
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.271:
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 [link moved to references]
 Fixed in 4.4.272:
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

if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.276-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"4.4.276-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"4.4.276_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.276-x86-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"4.4.276_smp-x86-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.276-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"4.4.276-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"4.4.276_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.276-i586-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"4.4.276-x86_64-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"4.4.276_smp-i686-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.276-noarch-1", rls:"SLK14.2"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"4.4.276_smp-noarch-1", rls:"SLK14.2"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

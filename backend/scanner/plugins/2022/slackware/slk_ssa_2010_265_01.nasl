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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2010.265.01");
  script_cve_id("CVE-2010-3081", "CVE-2010-3301");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-05 07:49:10 +0000 (Thu, 05 May 2022)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-08-14 14:05:00 +0000 (Fri, 14 Aug 2020)");

  script_name("Slackware: Security Advisory (SSA:2010-265-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLKcurrent");

  script_xref(name:"Advisory-ID", value:"SSA:2010-265-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2010&m=slackware-security.548585");

  script_tag(name:"summary", value:"The remote host is missing an update for the '-bit' package(s) announced via the SSA:2010-265-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New kernel packages are available for Slackware x86_64 13.1, and -current to
fix security issues.


Here are the details from the Slackware64 13.1 ChangeLog:
+--------------------------+
patches/packages/linux-2.6.33.4-2/kernel-firmware-2.6.33.4-noarch-2.txz: Rebuilt.
patches/packages/linux-2.6.33.4-2/kernel-generic-2.6.33.4-x86_64-2.txz: Rebuilt.
 This kernel has been patched to fix security problems on x86_64:
 64-bit Compatibility Mode Stack Pointer Underflow (CVE-2010-3081).
 IA32 System Call Entry Point Vulnerability (CVE-2010-3301).
 These vulnerabilities allow local users to gain root privileges.
 For more information, see:
 [link moved to references]
 [link moved to references]
 (* Security fix *)
patches/packages/linux-2.6.33.4-2/kernel-headers-2.6.33.4-x86-2.txz: Rebuilt.
patches/packages/linux-2.6.33.4-2/kernel-huge-2.6.33.4-x86_64-2.txz: Rebuilt.
 Patched for CVE-2010-3081 and CVE-2010-3301.
 (* Security fix *)
patches/packages/linux-2.6.33.4-2/kernel-modules-2.6.33.4-x86_64-2.txz: Rebuilt.
patches/packages/linux-2.6.33.4-2/kernel-source-2.6.33.4-noarch-2.txz: Rebuilt.
 Patched for CVE-2010-3081 and CVE-2010-3301.
 (* Security fix *)
patches/packages/linux-2.6.33.4-2/kernels/*: Rebuilt.
 Patched for CVE-2010-3081 and CVE-2010-3301.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'-bit' package(s) on Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"2.6.33.4-noarch-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.33.4-x86_64-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.33.4-x86-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.33.4-x86_64-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.33.4-x86_64-2", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.33.4-noarch-2", rls:"SLKcurrent"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

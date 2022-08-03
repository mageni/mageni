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
  script_oid("1.3.6.1.4.1.25623.1.1.13.2009.342.01");
  script_cve_id("CVE-2009-1298");
  script_tag(name:"creation_date", value:"2022-04-21 12:12:27 +0000 (Thu, 21 Apr 2022)");
  script_version("2022-05-05T07:49:10+0000");
  script_tag(name:"last_modification", value:"2022-05-05 07:49:10 +0000 (Thu, 05 May 2022)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");

  script_name("Slackware: Security Advisory (SSA:2009-342-01)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLKcurrent");

  script_xref(name:"Advisory-ID", value:"SSA:2009-342-01");
  script_xref(name:"URL", value:"http://www.slackware.com/security/viewer.php?l=slackware-security&y=2009&m=slackware-security.603376");
  script_xref(name:"URL", value:"http://lkml.org/lkml/2009/11/25/104");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'kernel' package(s) announced via the SSA:2009-342-01 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"New Linux kernel packages are available for Slackware 13.0 and -current
to address a security issue. A kernel bug discovered by David Ford may
allow remote attackers to crash the kernel by sending an oversized IP
packet. While the impact on ordinary servers is still unclear (the
problem was noticed while running openvasd), we are issuing these kernel
packages as a preemptive measure.

For more information, see:
 [link moved to references]
 [link moved to references]


Here are the details from the Slackware 13.0 ChangeLog:
+--------------------------+
Tue Dec 8 20:44:44 UTC 2009
patches/packages/linux-2.6.29.6-3/:
 Added new kernels and kernel packages with a patch for CVE-2009-1298,
 a kernel bug where oversized IP packets cause a NULL pointer dereference
 and immediate hang.
 For more information, see:
 [link moved to references]
 [link moved to references]
 Be sure to reinstall LILO after upgrading the kernel packages.
 (* Security fix *)
+--------------------------+");

  script_tag(name:"affected", value:"'kernel' package(s) on Slackware current.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");


res = "";
report = "";

if(!isnull(res = isslkpkgvuln(pkg:"kernel-firmware", ver:"2.6.29.6-noarch-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.29.6-i486-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.29.6-x86_64-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.29.6_smp-i686-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.29.6-x86-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.29.6_smp-x86-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.29.6-i486-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.29.6-x86_64-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"2.6.29.6_smp-i686-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.29.6-i486-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.29.6-x86_64-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"2.6.29.6_smp-i686-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.29.6-noarch-3", rls:"SLKcurrent"))) {
  report += res;
}
if(!isnull(res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.29.6_smp-noarch-3", rls:"SLKcurrent"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
exit(0);

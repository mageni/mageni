# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2009_230_01.nasl 14202 2019-03-15 09:16:15Z cfischer $
# Description: Auto-generated from the corresponding slackware advisory
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
  script_oid("1.3.6.1.4.1.25623.1.0.64771");
  script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $");
  script_cve_id("CVE-2009-2692");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_version("$Revision: 14202 $");
  script_name("Slackware Advisory SSA:2009-230-01 kernel");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK(12\.2|12\.1)");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-230-01");

  script_tag(name:"insight", value:"New Linux kernel packages are available for Slackware 12.2 and -current
to address a security issue.  A kernel bug discovered by Tavis Ormandy
and Julien Tinnes of the Google Security Team could allow a local user
to fill memory page zero with arbitrary code and then use the kernel
sendpage operation to trigger a NULL pointer dereference, executing the
code in the context of the kernel.  If successfully exploited, this bug
can be used to gain root access.

At this time we have prepared fixed kernels for the stable version of
Slackware (12.2), as well as for both 32-bit x86 and x86_64 -current
versions.  Additionally, we have added a package to the /patches
directory for Slackware 12.1 and 12.2 that will set the minimum memory
page that can be mmap()ed from userspace without additional privileges
to 4096.  The package will work with any kernel supporting the
vm.mmap_min_addr tunable, and should significantly reduce the potential
harm from this bug, as well as future similar bugs that might be found
in the kernel.  More updated kernels may follow.");

  script_tag(name:"solution", value:"Upgrade to the new package(s).");

  script_tag(name:"summary", value:"The remote host is missing an update as announced
via advisory SSA:2009-230-01.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

report = "";
res = "";

if((res = isslkpkgvuln(pkg:"kernel-firmware", ver:"2.6.27.31-noarch-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-generic", ver:"2.6.27.31-i486-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.27.31_smp-i686-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-headers", ver:"2.6.27.31_smp-x86-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-huge", ver:"2.6.27.31-i486-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-huge-smp", ver:"2.6.27.31_smp-i686-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-modules", ver:"2.6.27.31-i486-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"2.6.27.31_smp-i686-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.27.31_smp-noarch-1", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-mmap_min_addr", ver:"4096-noarch-1", rls:"SLK12.1")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-mmap_min_addr", ver:"4096-noarch-1", rls:"SLK12.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
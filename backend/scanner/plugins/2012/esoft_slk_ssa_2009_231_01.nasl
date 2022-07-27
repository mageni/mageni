# OpenVAS Vulnerability Test
# $Id: esoft_slk_ssa_2009_231_01.nasl 14202 2019-03-15 09:16:15Z cfischer $
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
  script_oid("1.3.6.1.4.1.25623.1.0.64770");
  script_tag(name:"creation_date", value:"2012-09-11 01:34:21 +0200 (Tue, 11 Sep 2012)");
  script_tag(name:"last_modification", value:"$Date: 2019-03-15 10:16:15 +0100 (Fri, 15 Mar 2019) $");
  script_version("$Revision: 14202 $");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Slackware Advisory SSA:2009-231-01 kernel [updated]");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 E-Soft Inc. http://www.securityspace.com");
  script_family("Slackware Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/slackware_linux", "ssh/login/slackpack", re:"ssh/login/release=SLK12\.2");

  script_xref(name:"URL", value:"https://secure1.securityspace.com/smysecure/catid.html?in=SSA:2009-231-01");

  script_tag(name:"insight", value:"This is a followup to the SSA:2009-230-01 advisory noting some errata.

The generic SMP kernel update for Slackware 12.2 was built using the
.config for a huge kernel, not a generic one.  The kernel previously
published as kernel-generic-smp and in the gemsmp.s directory works
and is secure, but is larger than it needs to be.  It has been
replaced in the Slackware 12.2 patches with a generic SMP kernel.

A new svgalib_helper package (compiled for a 2.6.27.31 kernel) was
added to the Slackware 12.2 /patches.

An error was noticed in the SSA:2009-230-01 advisory concerning the
packages for Slackware -current 32-bit.  The http links given refer to
packages with a -1 build version.  The actual packages have a build
number of -2.");

  script_tag(name:"solution", value:"Upgrade to the new package(s).");

  script_tag(name:"summary", value:"The remote host is missing an update as announced
via advisory SSA:2009-231-01.");

  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-slack.inc");

report = "";
res = "";

if((res = isslkpkgvuln(pkg:"kernel-modules-smp", ver:"2.6.27.31_smp-i686-2", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-generic-smp", ver:"2.6.27.31_smp-i686-2", rls:"SLK12.2")) != NULL) {
  report += res;
}
if((res = isslkpkgvuln(pkg:"kernel-source", ver:"2.6.27.31_smp-noarch-2", rls:"SLK12.2")) != NULL) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}
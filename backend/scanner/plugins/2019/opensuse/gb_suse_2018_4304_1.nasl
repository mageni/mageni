###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_4304_1.nasl 13338 2019-01-29 07:44:39Z mmartin $
#
# SuSE Update for xen openSUSE-SU-2018:4304-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2019 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.852221");
  script_version("$Revision: 13338 $");
  script_cve_id("CVE-2018-15468", "CVE-2018-15469", "CVE-2018-15470", "CVE-2018-18883", "CVE-2018-19961", "CVE-2018-19962", "CVE-2018-19965", "CVE-2018-19966", "CVE-2018-3646");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"last_modification", value:"$Date: 2019-01-29 08:44:39 +0100 (Tue, 29 Jan 2019) $");
  script_tag(name:"creation_date", value:"2019-01-01 04:01:26 +0100 (Tue, 01 Jan 2019)");
  script_name("SuSE Update for xen openSUSE-SU-2018:4304-1 (xen)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-12/msg00073.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the openSUSE-SU-2018:4304_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for xen fixes the following issues:

  Update to Xen 4.10.2 bug fix release (bsc#1027519).

  Security vulnerabilities fixed:

  - CVE-2018-19961, CVE-2018-19962: Fixed an issue related to insufficient
  TLB flushing with AMD IOMMUs, which potentially allowed a guest to
  escalate its privileges, may cause a Denial of Service (DoS) affecting
  the entire host, or may be able to access data it is not supposed to
  access. (XSA-275) (bsc#1115040)

  - CVE-2018-19965: Fixed an issue related to the INVPCID instruction in
  case non-canonical addresses are accessed, which may allow a guest to
  cause Xen to crash, resulting in a Denial of Service (DoS) affecting the
  entire host. (XSA-279) (bsc#1115045)

  - CVE-2018-19966: Fixed an issue related to a previous fix for XSA-240,
  which conflicted with shadow paging and allowed a guest to cause Xen to
  crash, resulting in a Denial of Service (DoS). (XSA-280) (bsc#1115047)

  - CVE-2018-18883: Fixed an issue related to improper restriction of nested
  VT-x, which allowed a guest to cause Xen to crash, resulting in a Denial
  of Service (DoS). (XSA-278) (bsc#1114405)

  - CVE-2018-15468: Fixed incorrect MSR_DEBUGCTL handling, which allowed
  guests to enable Branch Trace Store and may cause a Denial of Service
  (DoS) of the entire host. (XSA-269) (bsc#1103276)

  - CVE-2018-15469: Fixed use of v2 grant tables on ARM, which were not
  properly implemented and may cause a Denial of Service (DoS). (XSA-268)
  (bsc#1103275)

  - CVE-2018-15470: Fixed an issue in the logic in oxenstored for handling
  writes, which allowed a guest to write memory unbounded leading to
  system-wide Denial
  of Service (DoS). (XSA-272) (bsc#1103279)

  - CVE-2018-3646: Mitigations for VMM aspects of L1 Terminal Fault
  (XSA-273) (bsc#1091107)

  Other bugs fixed:

  - Fixed an issue related to a domU hang on SLE12-SP3 HV (bsc#1108940)

  - Fixed an issue with xpti=no-dom0 not working as expected (bsc#1105528)

  - Fixed a kernel oops related to fs/dcache.c called by
  d_materialise_unique() (bsc#1094508)

  This update was imported from the SUSE:SLE-15:Update update project.


  Patch Instructions:

  To install this openSUSE Security Update use the SUSE recommended
  installation methods
  like YaST online_update or 'zypper patch'.

  Alternatively you can run the command listed for your product:

  - openSUSE Leap 15.0:

  zypper in -t patch openSUSE-2018-1624=1");

  script_tag(name:"affected", value:"xen on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit-debuginfo", rpm:"xen-libs-32bit-debuginfo~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.10.2_04~lp150.2.12.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

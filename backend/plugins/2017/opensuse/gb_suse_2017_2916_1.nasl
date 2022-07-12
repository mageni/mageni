###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2017_2916_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2017:2916-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851639");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2017-11-01 21:48:37 +0100 (Wed, 01 Nov 2017)");
  script_cve_id("CVE-2017-15588", "CVE-2017-15589", "CVE-2017-15590", "CVE-2017-15591",
                "CVE-2017-15592", "CVE-2017-15593", "CVE-2017-15594", "CVE-2017-15595",
                "CVE-2017-5526");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen openSUSE-SU-2017:2916-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for xen fixes several issues:

  These security issues were fixed:

  - CVE-2017-5526: The ES1370 audio device emulation support was vulnerable
  to a memory leakage issue allowing a privileged user inside the guest to
  cause a DoS and/or potentially crash the Qemu process on the host
  (bsc#1059777)

  - CVE-2017-15593: Missing cleanup in the page type system allowed a
  malicious or buggy PV guest to cause DoS (XSA-242 bsc#1061084)

  - CVE-2017-15592: A problem in the shadow pagetable code allowed a
  malicious or buggy HVM guest to cause DoS or cause hypervisor memory
  corruption potentially allowing the guest to escalate its privilege
  (XSA-243 bsc#1061086)

  - CVE-2017-15594: Problematic handling of the selector fields in the
  Interrupt Descriptor Table (IDT) allowed a malicious or buggy x86 PV
  guest to escalate its privileges or cause DoS (XSA-244 bsc#1061087)

  - CVE-2017-15591: Missing checks in the handling of DMOPs allowed
  malicious or buggy stub domain kernels or tool stacks otherwise living
  outside of Domain0 to cause a DoS (XSA-238 bsc#1061077)

  - CVE-2017-15589: Intercepted I/O write operations with less than a full
  machine word's worth of data were not properly handled, which allowed a
  malicious unprivileged x86 HVM guest to obtain sensitive information
  from the host or
  other guests (XSA-239 bsc#1061080)

  - CVE-2017-15595: In certain configurations of linear page tables a stack
  overflow might have occurred that allowed a malicious or buggy PV guest
  to cause DoS and potentially privilege escalation and information leaks
  (XSA-240 bsc#1061081)

  - CVE-2017-15588: Under certain conditions x86 PV guests could have caused
  the hypervisor to miss a necessary TLB flush for a page. This allowed a
  malicious x86 PV guest to access all of system memory, allowing for
  privilege escalation, DoS, and information leaks (XSA-241 bsc#1061082)

  - CVE-2017-15590: Multiple issues existed with the setup of PCI MSI
  interrupts that allowed a malicious or buggy guest to cause DoS and
  potentially privilege escalation and information leaks (XSA-237
  bsc#1061076)

  This non-security issue was fixed:

  - bsc#1057358: Fixed boot when secure boot is enabled

  This update was imported from the SUSE:SLE-12-SP2:Update update project.");
  script_tag(name:"affected", value:"xen on openSUSE Leap 42.2");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.2")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.7.3_06~11.18.1", rls:"openSUSELeap42.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

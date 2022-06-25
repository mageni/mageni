###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2015_2003_1.nasl 12381 2018-11-16 11:16:30Z cfischer $
#
# SuSE Update for xen openSUSE-SU-2015:2003-1 (xen)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851134");
  script_version("$Revision: 12381 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-16 12:16:30 +0100 (Fri, 16 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-18 06:36:20 +0100 (Wed, 18 Nov 2015)");
  script_cve_id("CVE-2014-0222", "CVE-2015-3259", "CVE-2015-4037", "CVE-2015-5154",
                "CVE-2015-5165", "CVE-2015-5166", "CVE-2015-5239", "CVE-2015-6815",
                "CVE-2015-7311", "CVE-2015-7835", "CVE-2015-7969", "CVE-2015-7971",
                "CVE-2015-7972");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for xen openSUSE-SU-2015:2003-1 (xen)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'xen'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"xen was updated to fix 12 security issues.

  These security issues were fixed:

  - CVE-2015-7972: Populate-on-demand balloon size inaccuracy can crash
  guests (bsc#951845).

  - CVE-2015-7969: Leak of main per-domain vcpu pointer array (DoS)
  (bsc#950703).

  - CVE-2015-7969: Leak of per-domain profiling-related vcpu pointer array
  (DoS) (bsc#950705).

  - CVE-2015-7971: Some pmu and profiling hypercalls log without rate
  limiting (bsc#950706).

  - CVE-2015-4037: Insecure temporary file use in /net/slirp.c (bsc#932267).

  - CVE-2014-0222: Validate L2 table size to avoid integer overflows
  (bsc#877642).

  - CVE-2015-7835: Uncontrolled creation of large page mappings by PV guests
  (bsc#950367).

  - CVE-2015-7311: libxl fails to honour readonly flag on disks with
  qemu-xen (bsc#947165).

  - CVE-2015-5165: QEMU leak of uninitialized heap memory in rtl8139 device
  model (bsc#939712).

  - CVE-2015-5166: Use after free in QEMU/Xen block unplug protocol
  (bsc#939709).

  - CVE-2015-5154: Host code execution via IDE subsystem CD-ROM (bsc#938344).

  - CVE-2015-3259: xl command line config handling stack overflow
  (bsc#935634).

  These non-security issues were fixed:

  - bsc#907514: Bus fatal error and sles12 sudden reboot has been observed

  - bsc#910258: SLES12 Xen host crashes with FATAL NMI after shutdown of
  guest with VT-d NIC

  - bsc#918984: Bus fatal error and sles11-SP4 sudden reboot has been
  observed

  - bsc#923967: Partner-L3: Bus fatal error and sles11-SP3 sudden reboot has
  been observed

  - bsc#901488: Intel ixgbe driver assigns rx/tx queues per core resulting
  in irq problems on servers with a large amount of CPU cores

  - bsc#945167: Running command xl pci-assignable-add 03:10.1 secondly show
  errors

  - bsc#949138: Setting vcpu affinity under Xen causes libvirtd abort

  - bsc#944463: VUL-0: CVE-2015-5239: qemu-kvm: Integer overflow in
  vnc_client_read() and protocol_client_msg()

  - bsc#944697: VUL-1: CVE-2015-6815: qemu: net: e1000: infinite loop issue

  - bsc#925466: Kdump does not work in a XEN environment");
  script_tag(name:"affected", value:"xen on openSUSE 13.2");
  script_tag(name:"solution", value:"Please install the updated packages.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSE13\.2");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSE13.2")
{

  if ((res = isrpmvuln(pkg:"xen-debugsource", rpm:"xen-debugsource~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-devel", rpm:"xen-devel~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs", rpm:"xen-libs~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo", rpm:"xen-libs-debuginfo~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU", rpm:"xen-tools-domU~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-domU-debuginfo", rpm:"xen-tools-domU-debuginfo~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen", rpm:"xen~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-doc-html", rpm:"xen-doc-html~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default", rpm:"xen-kmp-default~4.4.3_02_k3.16.7_29~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-default-debuginfo", rpm:"xen-kmp-default-debuginfo~4.4.3_02_k3.16.7_29~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop", rpm:"xen-kmp-desktop~4.4.3_02_k3.16.7_29~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-kmp-desktop-debuginfo", rpm:"xen-kmp-desktop-debuginfo~4.4.3_02_k3.16.7_29~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-32bit", rpm:"xen-libs-32bit~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-libs-debuginfo-32bit", rpm:"xen-libs-debuginfo-32bit~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools", rpm:"xen-tools~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"xen-tools-debuginfo", rpm:"xen-tools-debuginfo~4.4.3_02~30.1", rls:"openSUSE13.2")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

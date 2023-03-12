# Copyright (C) 2023 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.479");
  script_cve_id("CVE-2015-2752", "CVE-2015-2756", "CVE-2015-5165", "CVE-2015-5307", "CVE-2015-7969", "CVE-2015-7970", "CVE-2015-7971", "CVE-2015-7972", "CVE-2015-8104", "CVE-2015-8339", "CVE-2015-8340", "CVE-2015-8550", "CVE-2015-8554", "CVE-2015-8555", "CVE-2015-8615", "CVE-2016-1570", "CVE-2016-1571", "CVE-2016-2270", "CVE-2016-2271");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-11 14:52:00 +0000 (Fri, 11 Feb 2022)");

  script_name("Debian: Security Advisory (DLA-479)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-479");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-479");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DLA-479 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This security update fixes a number of security issues in Xen in wheezy.

For Debian 7 Wheezy, these problems have been fixed in version 4.1.6.1-1+deb7u1.

We recommend that you upgrade your libidn packages.

CVE-2015-2752

The XEN_DOMCTL_memory_mapping hypercall in Xen 3.2.x through 4.5.x, when using a PCI passthrough device, is not preemptable, which allows local x86 HVM domain users to cause a denial of service (host CPU consumption) via a crafted request to the device model (qemu-dm).

CVE-2015-2756

QEMU, as used in Xen 3.3.x through 4.5.x, does not properly restrict access to PCI command registers, which might allow local HVM guest users to cause a denial of service (non-maskable interrupt and host crash) by disabling the (1) memory or (2) I/O decoding for a PCI Express device and then accessing the device, which triggers an Unsupported Request (UR) response.

CVE-2015-5165

The C+ mode offload emulation in the RTL8139 network card device model in QEMU, as used in Xen 4.5.x and earlier, allows remote attackers to read process heap memory via unspecified vectors.

CVE-2015-5307

The KVM subsystem in the Linux kernel through 4.2.6, and Xen 4.3.x through 4.6.x, allows guest OS users to cause a denial of service (host OS panic or hang) by triggering many #AC (aka Alignment Check) exceptions, related to svm.c and vmx.c.

CVE-2015-7969

Multiple memory leaks in Xen 4.0 through 4.6.x allow local guest administrators or domains with certain permission to cause a denial of service (memory consumption) via a large number of teardowns of domains with the vcpu pointer array allocated using the (1) XEN_DOMCTL_max_vcpus hypercall or the xenoprofile state vcpu pointer array allocated using the (2) XENOPROF_get_buffer or (3) XENOPROF_set_passive hypercall.

CVE-2015-7970

The p2m_pod_emergency_sweep function in arch/x86/mm/p2m-pod.c in Xen 3.4.x, 3.5.x, and 3.6.x is not preemptible, which allows local x86 HVM guest administrators to cause a denial of service (CPU consumption and possibly reboot) via crafted memory contents that triggers a 'time-consuming linear scan,' related to Populate-on-Demand.

CVE-2015-7971

Xen 3.2.x through 4.6.x does not limit the number of printk console messages when logging certain pmu and profiling hypercalls, which allows local guests to cause a denial of service via a sequence of crafted (1) HYPERCALL_xenoprof_op hypercalls, which are not properly handled in the do_xenoprof_op function in common/xenoprof.c, or (2) HYPERVISOR_xenpmu_op hypercalls, which are not properly handled in the do_xenpmu_op function in arch/x86/cpu/vpmu.c.

CVE-2015-7972

The (1) libxl_set_memory_target function in tools/libxl/libxl.c and (2) libxl__build_post function in tools/libxl/libxl_dom.c in Xen 3.4.x through 4.6.x do not properly calculate the balloon size when using the populate-on-demand (PoD) system, which allows local HVM guest users to cause a denial of service ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'xen' package(s) on Debian 7.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

release = dpkg_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "DEB7") {

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.1", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-ocaml-dev", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-ocaml", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-docs-4.1", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.1-amd64", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.1-i386", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-i386", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.1", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.1.6.1-1+deb7u1", rls:"DEB7"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

exit(0);

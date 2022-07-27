# Copyright (C) 2019 Greenbone Networks GmbH
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (C) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.704567");
  script_version("2019-11-14T03:00:17+0000");
  script_cve_id("CVE-2019-14818");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2019-11-14 03:00:17 +0000 (Thu, 14 Nov 2019)");
  script_tag(name:"creation_date", value:"2019-11-14 03:00:17 +0000 (Thu, 14 Nov 2019)");
  script_name("Debian Security Advisory DSA 4567-1 (dpdk - security update)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(10|9)");

  script_xref(name:"URL", value:"https://www.debian.org/security/2019/dsa-4567.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-4567-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dpdk'
  package(s) announced via the DSA-4567-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that the vhost PMD in DPDK, a set of libraries for
fast packet processing, was affected by memory and file descriptor leaks
which could result in denial of service.");

  script_tag(name:"affected", value:"'dpdk' package(s) on Debian Linux.");

  script_tag(name:"solution", value:"For the oldstable distribution (stretch), this problem has been fixed
in version 16.11.9-1+deb9u2.

For the stable distribution (buster), this problem has been fixed in
version 18.11.2-2+deb10u2.

We recommend that you upgrade your dpdk packages.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if(!isnull(res = isdpkgvuln(pkg:"dpdk", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-dev", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-doc", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-igb-uio-dkms", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-rte-kni-dkms", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdpdk-dev", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-acl18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bbdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bitratestats18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bpf18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bus-dpaa18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bus-fslmc18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bus-ifpga18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bus-pci18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bus-vdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-bus-vmbus18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cfgfile18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cmdline18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-common-cpt18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-common-dpaax18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-common-octeontx18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-compressdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cryptodev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-distributor18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-eal18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-efd18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-ethdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-eventdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-flow-classify18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-gro18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-gso18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-hash18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-ip-frag18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-jobstats18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-kni18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-kvargs18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-latencystats18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-lpm18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mbuf18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-member18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool-bucket18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool-dpaa18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool-dpaa2-18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool-octeontx18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool-ring18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool-stack18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-meter18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-metrics18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-net18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pci18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pdump18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pipeline18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-aesni-gcm18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-aesni-mb18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-af-packet18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ark18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-atlantic18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-avf18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-avp18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-axgbe18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-bbdev-null18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-bnx2x18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-bnxt18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-bond18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-caam-jr18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ccp18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-crypto-scheduler18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-cxgbe18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa-sec18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa2-18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa2-cmdif18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa2-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa2-qdma18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dpaa2-sec18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-dsw-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-e1000-18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ena18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-enetc18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-enic18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-failsafe18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-fm10k18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-i40e18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ifc18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ifpga-rawdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ixgbe18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-kni18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-liquidio18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-mlx4-18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-mlx5-18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-netvsc18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-nfp18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-null-crypto18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-null18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-octeontx-compress18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-octeontx-crypto18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-octeontx-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-octeontx18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-opdl-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-openssl18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-pcap18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-qat18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-qede18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ring18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-sfc18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-skeleton-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-skeleton-rawdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-softnic18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-sw-event18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-tap18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-thunderx18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-vdev-netvsc18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-vhost18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-virtio-crypto18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-virtio18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-vmxnet3-18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-zlib18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-port18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-power18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-rawdev18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-reorder18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-ring18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-sched18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-security18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-table18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-telemetry18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-timer18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-vhost18.11", ver:"18.11.2-2+deb10u2", rls:"DEB10"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-dev", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-doc", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-igb-uio-dkms", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"dpdk-rte-kni-dkms", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libdpdk-dev", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"libethdev4", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-acl2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cfgfile2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cmdline2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cryptodev1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-cryptodev2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-distributor1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-eal2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-eal3", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-ethdev5", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-hash2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-ip-frag1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-jobstats1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-kni2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-kvargs1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-lpm2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mbuf2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-mempool2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-meter1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-net1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pdump1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pipeline3", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-af-packet1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-bnxt1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-bond1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-cxgbe1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-e1000-1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ena1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-enic1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-fm10k1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-i40e1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ixgbe1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-null-crypto1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-null1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-pcap1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-qede1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-ring2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-vhost1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-virtio1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-vmxnet3-uio1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-pmd-xenvirt1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-port3", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-power1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-reorder1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-ring1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-sched1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-table2", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-timer1", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}
if(!isnull(res = isdpkgvuln(pkg:"librte-vhost3", ver:"16.11.9-1+deb9u2", rls:"DEB9"))) {
  report += res;
}

if(report != "") {
  security_message(data:report);
} else if(__pkg_match) {
  exit(99);
}

exit(0);
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
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2016.571");
  script_cve_id("CVE-2014-3672", "CVE-2016-3158", "CVE-2016-3159", "CVE-2016-3710", "CVE-2016-3712", "CVE-2016-3960", "CVE-2016-4480", "CVE-2016-6258");
  script_tag(name:"creation_date", value:"2023-03-08 12:56:44 +0000 (Wed, 08 Mar 2023)");
  script_version("2023-03-09T10:09:19+0000");
  script_tag(name:"last_modification", value:"2023-03-09 10:09:19 +0000 (Thu, 09 Mar 2023)");
  script_tag(name:"cvss_base", value:"7.2");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2017-07-01 01:29:00 +0000 (Sat, 01 Jul 2017)");

  script_name("Debian: Security Advisory (DLA-571)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB7");

  script_xref(name:"Advisory-ID", value:"DLA-571");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2016/dla-571");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'xen' package(s) announced via the DLA-571 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities have been discovered in the Xen hypervisor. The Common Vulnerabilities and Exposures project identifies the following problems:

CVE-2014-3672 (XSA-180) Andrew Sorensen discovered that a HVM domain can exhaust the hosts disk space by filling up the log file.

CVE-2016-3158 / CVE-2016-3159 (XSA-172) Jan Beulich from SUSE discovered that Xen does not properly handle writes to the hardware FSW.ES bit when running on AMD64 processors. A malicious domain can take advantage of this flaw to obtain address space usage and timing information, about another domain, at a fairly low rate.

CVE-2016-3710 (XSA-179) Wei Xiao and Qinghao Tang of 360.cn Inc discovered an out-of-bounds read and write flaw in the QEMU VGA module. A privileged guest user could use this flaw to execute arbitrary code on the host with the privileges of the hosting QEMU process.

CVE-2016-3712 (XSA-179) Zuozhi Fzz of Alibaba Inc discovered potential integer overflow or out-of-bounds read access issues in the QEMU VGA module. A privileged guest user could use this flaw to mount a denial of service (QEMU process crash).

CVE-2016-3960 (XSA-173) Ling Liu and Yihan Lian of the Cloud Security Team, Qihoo 360 discovered an integer overflow in the x86 shadow pagetable code. A HVM guest using shadow pagetables can cause the host to crash. A PV guest using shadow pagetables (i.e. being migrated) with PV superpages enabled (which is not the default) can crash the host, or corrupt hypervisor memory, potentially leading to privilege escalation.

CVE-2016-4480 (XSA-176) Jan Beulich discovered that incorrect page table handling could result in privilege escalation inside a Xen guest instance.

CVE-2016-6258 (XSA-182) Jeremie Boutoille discovered that incorrect pagetable handling in PV instances could result in guest to host privilege escalation.

Additionally this Xen Security Advisory without a CVE was fixed: XSA-166 Konrad Rzeszutek Wilk and Jan Beulich discovered that ioreq handling is possibly susceptible to a multiple read issue.

For Debian 7 Wheezy, these problems have been fixed in version 4.1.6.lts1-1.

We recommend that you upgrade your xen packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

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

  if(!isnull(res = isdpkgvuln(pkg:"libxen-4.1", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-dev", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-ocaml-dev", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxen-ocaml", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libxenstore3.0", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-docs-4.1", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.1-amd64", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-hypervisor-4.1-i386", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-amd64", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-system-i386", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-4.1", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xen-utils-common", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xenstore-utils", ver:"4.1.6.lts1-1", rls:"DEB7"))) {
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

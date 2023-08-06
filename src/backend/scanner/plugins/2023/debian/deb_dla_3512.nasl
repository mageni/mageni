# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3512");
  script_cve_id("CVE-2023-20593", "CVE-2023-2156", "CVE-2023-31248", "CVE-2023-3390", "CVE-2023-35001", "CVE-2023-3610");
  script_tag(name:"creation_date", value:"2023-08-04 04:22:52 +0000 (Fri, 04 Aug 2023)");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-31 17:28:00 +0000 (Mon, 31 Jul 2023)");

  script_name("Debian: Security Advisory (DLA-3512)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3512");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3512");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/linux-5.10");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'linux-5.10' package(s) announced via the DLA-3512 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"CVE-2023-31248 CVE-2023-35001

Several vulnerabilities have been discovered in the Linux kernel that may lead to a privilege escalation, denial of service or information leaks.

CVE-2023-2156

It was discovered that a flaw in the handling of the RPL protocol may allow an unauthenticated remote attacker to cause a denial of service if RPL is enabled (not by default in Debian).

CVE-2023-3390

A use-after-free flaw in the netfilter subsystem caused by incorrect error path handling may result in denial of service or privilege escalation.

CVE-2023-3610

A use-after-free flaw in the netfilter subsystem caused by incorrect refcount handling on the table and chain destroy path may result in denial of service or privilege escalation.

CVE-2023-20593

Tavis Ormandy discovered that under specific microarchitectural circumstances, a vector register in AMD Zen 2 CPUs may not be written to 0 correctly. This flaw allows an attacker to leak sensitive information across concurrent processes, hyper threads and virtualized guests.

For details please refer to and .

This issue can also be mitigated by a microcode update through the amd64-microcode package or a system firmware (BIOS/UEFI) update. However, the initial microcode release by AMD only provides updates for second generation EPYC CPUs. Various Ryzen CPUs are also affected, but no updates are available yet.

CVE-2023-31248

Mingi Cho discovered a use-after-free flaw in the Netfilter nf_tables implementation when using nft_chain_lookup_byid, which may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

CVE-2023-35001

Tanguy DUBROCA discovered an out-of-bounds reads and write flaw in the Netfilter nf_tables implementation when processing an nft_byteorder expression, which may result in local privilege escalation for a user with the CAP_NET_ADMIN capability in any user or network namespace.

For Debian 10 buster, these problems have been fixed in version 5.10.179-3~deb10u1.

We recommend that you upgrade your linux-5.10 packages.

For the detailed security status of linux-5.10 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'linux-5.10' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-doc-5.10", ver:"5.10.179-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-common", ver:"5.10.179-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-headers-5.10.0-0.deb10.23-common-rt", ver:"5.10.179-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-source-5.10", ver:"5.10.179-3~deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-support-5.10.0-0.deb10.23", ver:"5.10.179-3~deb10u1", rls:"DEB10"))) {
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

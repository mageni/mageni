# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6355.1");
  script_cve_id("CVE-2021-3695", "CVE-2021-3696", "CVE-2021-3697", "CVE-2021-3981", "CVE-2022-28733", "CVE-2022-28734", "CVE-2022-28735", "CVE-2022-28736", "CVE-2022-28737", "CVE-2022-3775");
  script_tag(name:"creation_date", value:"2023-09-08 04:08:46 +0000 (Fri, 08 Sep 2023)");
  script_version("2023-09-11T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-09-11 05:05:16 +0000 (Mon, 11 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-28 15:34:00 +0000 (Fri, 28 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6355-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6355-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6355-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2029518");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'grub2-signed, grub2-unsigned, shim, shim-signed' package(s) announced via the USN-6355-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Axtens discovered that specially crafted images could cause a
heap-based out-of-bonds write. A local attacker could possibly use
this to circumvent secure boot protections. (CVE-2021-3695)

Daniel Axtens discovered that specially crafted images could cause
out-of-bonds read and write. A local attacker could possibly use this
to circumvent secure boot protections. (CVE-2021-3696)

Daniel Axtens discovered that specially crafted images could cause
buffer underwrite which allows arbitrary data to be written to a heap.
A local attacker could possibly use this to circumvent secure
boot protections. (CVE-2021-3697)

It was discovered that GRUB2 configuration files were created with
the wrong permissions. An attacker could possibly use this to leak
encrypted passwords. (CVE-2021-3981)

Daniel Axtens discovered that specially crafted IP packets could cause
an integer underflow and write past the end of a buffer. An attacker
could possibly use this to circumvent secure boot protections.
(CVE-2022-28733)

Daniel Axtens discovered that specially crafted HTTP headers can cause
an out-of-bounds write of a NULL byte. An attacker could possibly use
this to corrupt GRUB2's internal data. (CVE-2022-28734)

Julian Andres Klode discovered that GRUB2 shim_lock allowed non-
kernel files to be loaded. A local attack could possibly use this to
circumvent secure boot protections. (CVE-2022-28735)

Chris Coulson discovered that executing chainloaders more than once
caused a use-after-free vulnerability. A local attack could possibly
use this to circumvent secure boot protections. (CVE-2022-28736)

Chris Coulson discovered that specially crafted executables could
cause shim to make out-of-bound writes. A local attack could possibly
use this to circumvent secure boot protections. (CVE-2022-28737)

Zhang Boyang discovered that specially crafted unicode sequences
could lead to an out-of-bounds write to a heap. A local attacker could
possibly use this to circumvent secure boot protections.
(CVE-2022-3775)");

  script_tag(name:"affected", value:"'grub2-signed, grub2-unsigned, shim, shim-signed' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64", ver:"2.06-2ubuntu14.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.06-2ubuntu14.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.187.3~20.04.1+2.06-2ubuntu14.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64", ver:"2.06-2ubuntu14.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.06-2ubuntu14.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.187.3~20.04.1+2.06-2ubuntu14.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"shim", ver:"15.7-0ubuntu1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"shim-signed", ver:"1.40.9+15.7-0ubuntu1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64", ver:"2.06-2ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-bin", ver:"2.06-2ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-amd64-signed", ver:"1.187.3~22.04.1+2.06-2ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64", ver:"2.06-2ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-bin", ver:"2.06-2ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"grub-efi-arm64-signed", ver:"1.187.3~22.04.1+2.06-2ubuntu14.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"shim", ver:"15.7-0ubuntu1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"shim-signed", ver:"1.51.3+15.7-0ubuntu1", rls:"UBUNTU22.04 LTS"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6388.1");
  script_cve_id("CVE-2022-40982", "CVE-2023-3212", "CVE-2023-32269", "CVE-2023-3863", "CVE-2023-40283", "CVE-2023-4128", "CVE-2023-4385", "CVE-2023-4387", "CVE-2023-4459");
  script_tag(name:"creation_date", value:"2023-09-20 04:08:41 +0000 (Wed, 20 Sep 2023)");
  script_version("2023-09-20T05:05:13+0000");
  script_tag(name:"last_modification", value:"2023-09-20 05:05:13 +0000 (Wed, 20 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-16 20:32:00 +0000 (Wed, 16 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6388-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6388-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6388-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) announced via the USN-6388-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Daniel Moghimi discovered that some Intel(R) Processors did not properly
clear microarchitectural state after speculative execution of various
instructions. A local unprivileged user could use this to obtain to
sensitive information. (CVE-2022-40982)

Yang Lan discovered that the GFS2 file system implementation in the Linux
kernel could attempt to dereference a null pointer in some situations. An
attacker could use this to construct a malicious GFS2 image that, when
mounted and operated on, could cause a denial of service (system crash).
(CVE-2023-3212)

It was discovered that the NET/ROM protocol implementation in the Linux
kernel contained a race condition in some situations, leading to a use-
after-free vulnerability. A local attacker could use this to cause a denial
of service (system crash) or possibly execute arbitrary code.
(CVE-2023-32269)

It was discovered that the NFC implementation in the Linux kernel contained
a use-after-free vulnerability when performing peer-to-peer communication
in certain conditions. A privileged attacker could use this to cause a
denial of service (system crash) or possibly expose sensitive information
(kernel memory). (CVE-2023-3863)

It was discovered that the bluetooth subsystem in the Linux kernel did not
properly handle L2CAP socket release, leading to a use-after-free
vulnerability. A local attacker could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-40283)

It was discovered that some network classifier implementations in the Linux
kernel contained use-after-free vulnerabilities. A local attacker could use
this to cause a denial of service (system crash) or possibly execute
arbitrary code. (CVE-2023-4128)

It was discovered that the JFS file system implementation in the Linux
kernel did not properly validate memory allocations in certain situations,
leading to a null pointer dereference vulnerability. An attacker could use
this to construct a malicious JFS image that, when mounted, could cause a
denial of service (system crash). (CVE-2023-4385)

It was discovered that the VMware VMXNET3 ethernet driver in the Linux
kernel contained a use-after-free vulnerability in certain situations. A
local attacker in a guest VM could use this to cause a denial of service
(system crash) or possibly execute arbitrary code. (CVE-2023-4387)

It was discovered that the VMware VMXNET3 ethernet driver in the Linux
kernel did not properly handle errors in certain situations, leading to a
null pointer dereference vulnerability. A local attacker in a guest VM
could use this to cause a denial of service (system crash). (CVE-2023-4459)");

  script_tag(name:"affected", value:"'linux, linux-aws, linux-kvm, linux-lts-xenial' package(s) on Ubuntu 14.04, Ubuntu 16.04.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1123-aws", ver:"4.4.0-1123.129", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-245-generic", ver:"4.4.0-245.279~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-245-lowlatency", ver:"4.4.0-245.279~14.04.1", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1123.120", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.245.213", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.245.213", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.245.213", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1124-kvm", ver:"4.4.0-1124.134", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-1161-aws", ver:"4.4.0-1161.176", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-245-generic", ver:"4.4.0-245.279", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-4.4.0-245-lowlatency", ver:"4.4.0-245.279", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-aws", ver:"4.4.0.1161.165", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic", ver:"4.4.0.245.251", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-generic-lts-xenial", ver:"4.4.0.245.251", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-kvm", ver:"4.4.0.1124.121", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency", ver:"4.4.0.245.251", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-lowlatency-lts-xenial", ver:"4.4.0.245.251", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual", ver:"4.4.0.245.251", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-virtual-lts-xenial", ver:"4.4.0.245.251", rls:"UBUNTU16.04 LTS"))) {
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

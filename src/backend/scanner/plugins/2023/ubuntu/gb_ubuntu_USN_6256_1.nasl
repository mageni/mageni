# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6256.1");
  script_cve_id("CVE-2022-3108", "CVE-2022-3707", "CVE-2022-3903", "CVE-2022-4129", "CVE-2023-0458", "CVE-2023-0459", "CVE-2023-1073", "CVE-2023-1074", "CVE-2023-1075", "CVE-2023-1076", "CVE-2023-1077", "CVE-2023-1078", "CVE-2023-1079", "CVE-2023-1118", "CVE-2023-1281", "CVE-2023-1380", "CVE-2023-1513", "CVE-2023-1670", "CVE-2023-1829", "CVE-2023-1859", "CVE-2023-1998", "CVE-2023-2162", "CVE-2023-25012", "CVE-2023-2612", "CVE-2023-26545", "CVE-2023-2985", "CVE-2023-30456", "CVE-2023-31436", "CVE-2023-3161", "CVE-2023-32233", "CVE-2023-32269", "CVE-2023-35788");
  script_tag(name:"creation_date", value:"2023-07-27 04:09:33 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-07-28T05:05:23+0000");
  script_tag(name:"last_modification", value:"2023-07-28 05:05:23 +0000 (Fri, 28 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-23 21:19:00 +0000 (Fri, 23 Jun 2023)");

  script_name("Ubuntu: Security Advisory (USN-6256-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6256-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6256-1");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023220");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2023577");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'linux-iot' package(s) announced via the USN-6256-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jiasheng Jiang discovered that the HSA Linux kernel driver for AMD Radeon
GPU devices did not properly validate memory allocation in certain
situations, leading to a null pointer dereference vulnerability. A local
attacker could use this to cause a denial of service (system crash).
(CVE-2022-3108)

Zheng Wang discovered that the Intel i915 graphics driver in the Linux
kernel did not properly handle certain error conditions, leading to a
double-free. A local attacker could possibly use this to cause a denial of
service (system crash). (CVE-2022-3707)

It was discovered that the infrared transceiver USB driver did not properly
handle USB control messages. A local attacker with physical access could
plug in a specially crafted USB device to cause a denial of service (memory
exhaustion). (CVE-2022-3903)

Haowei Yan discovered that a race condition existed in the Layer 2
Tunneling Protocol (L2TP) implementation in the Linux kernel. A local
attacker could possibly use this to cause a denial of service (system
crash). (CVE-2022-4129)

Jordy Zomer and Alexandra Sandulescu discovered that syscalls invoking the
do_prlimit() function in the Linux kernel did not properly handle
speculative execution barriers. A local attacker could use this to expose
sensitive information (kernel memory). (CVE-2023-0458)

Jordy Zomer and Alexandra Sandulescu discovered that the Linux kernel did
not properly implement speculative execution barriers in usercopy functions
in certain situations. A local attacker could use this to expose sensitive
information (kernel memory). (CVE-2023-0459)

It was discovered that the Human Interface Device (HID) support driver in
the Linux kernel contained a type confusion vulnerability in some
situations. A local attacker could use this to cause a denial of service
(system crash). (CVE-2023-1073)

It was discovered that a memory leak existed in the SCTP protocol
implementation in the Linux kernel. A local attacker could use this to
cause a denial of service (memory exhaustion). (CVE-2023-1074)

It was discovered that the TLS subsystem in the Linux kernel contained a
type confusion vulnerability in some situations. A local attacker could use
this to cause a denial of service (system crash) or possibly expose
sensitive information. (CVE-2023-1075)

It was discovered that the TUN/TAP driver in the Linux kernel did not
properly initialize socket data. A local attacker could use this to cause a
denial of service (system crash). (CVE-2023-1076)

It was discovered that the Real-Time Scheduling Class implementation in the
Linux kernel contained a type confusion vulnerability in some situations. A
local attacker could use this to cause a denial of service (system crash).
(CVE-2023-1077)

It was discovered that the Reliable Datagram Sockets (RDS) protocol
implementation in the Linux kernel contained a type confusion vulnerability
in some situations. An attacker could use this ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'linux-iot' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"linux-image-5.4.0-1017-iot", ver:"5.4.0-1017.18", rls:"UBUNTU20.04 LTS"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885238");
  script_version("2023-12-14T05:05:32+0000");
  script_cve_id("CVE-2023-5871");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-12-14 05:05:32 +0000 (Thu, 14 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-11 19:33:00 +0000 (Mon, 11 Dec 2023)");
  script_tag(name:"creation_date", value:"2023-11-09 02:15:50 +0000 (Thu, 09 Nov 2023)");
  script_name("Fedora: Security Advisory for libnbd (FEDORA-2023-00c130636a)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-00c130636a");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KL2X5SSJS4O4WTOQKXFE3323NL4IBNQG");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libnbd'
  package(s) announced via the FEDORA-2023-00c130636a advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"NBD  Network Block Device  is a protocol for accessing Block Devices
(hard disks and disk-like things) over a Network.

This is the NBD client library in userspace, a simple library for
writing NBD clients.

The key features are:

  * Synchronous and asynchronous APIs, both for ease of use and for
   writing non-blocking, multithreaded clients.

  * High performance.

  * Minimal dependencies for the basic library.

  * Well-documented, stable API.

  * Bindings in several programming languages.");

  script_tag(name:"affected", value:"'libnbd' package(s) on Fedora 39.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"libnbd", rpm:"libnbd~1.18.1~2.fc39", rls:"FC39"))) {
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
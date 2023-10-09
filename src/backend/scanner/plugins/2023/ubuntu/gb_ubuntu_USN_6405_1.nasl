# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6405.1");
  script_cve_id("CVE-2023-3600", "CVE-2023-4057", "CVE-2023-4577", "CVE-2023-4578", "CVE-2023-4580", "CVE-2023-4583", "CVE-2023-4585", "CVE-2023-5169", "CVE-2023-5171", "CVE-2023-5176", "CVE-2023-5217");
  script_tag(name:"creation_date", value:"2023-10-04 04:08:40 +0000 (Wed, 04 Oct 2023)");
  script_version("2023-10-04T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-10-04 05:06:18 +0000 (Wed, 04 Oct 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-29 15:17:00 +0000 (Fri, 29 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6405-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6405-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6405-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird' package(s) announced via the USN-6405-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Thunderbird. If a user were
tricked into opening a specially crafted website in a browsing context, an
attacker could potentially exploit these to cause a denial of service,
obtain sensitive information, bypass security restrictions, cross-site
tracing, or execute arbitrary code. (CVE-2023-4057, CVE-2023-4577,
CVE-2023-4578, CVE-2023-4583, CVE-2023-4585, CVE-2023-5169, CVE-2023-5171,
CVE-2023-5176)

Andrew McCreight discovered that Thunderbird did not properly manage during
the worker lifecycle. An attacker could potentially exploit this issue to
cause a denial of service. (CVE-2023-3600)

Harveer Singh discovered that Thunderbird did not store push notifications
in private browsing mode in encrypted form. An attacker could potentially
exploit this issue to obtain sensitive information. (CVE-2023-4580)

Clement Lecigne discovered that Thunderbird did not properly manage memory
when handling VP8 media stream. An attacker-controlled VP8 media stream
could lead to a heap buffer overflow in the content process, resulting in a
denial of service, or possibly execute arbitrary code. (CVE-2023-5217)");

  script_tag(name:"affected", value:"'thunderbird' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.3.1+build1-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.3.1+build1-0ubuntu0.22.04.2", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"thunderbird", ver:"1:115.3.1+build1-0ubuntu0.23.04.1", rls:"UBUNTU23.04"))) {
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

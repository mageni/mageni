# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6622.1");
  script_cve_id("CVE-2023-5678", "CVE-2023-6129", "CVE-2023-6237", "CVE-2024-0727");
  script_tag(name:"creation_date", value:"2024-02-06 04:08:43 +0000 (Tue, 06 Feb 2024)");
  script_version("2024-02-06T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-06 05:05:38 +0000 (Tue, 06 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:P/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-23 21:32:01 +0000 (Tue, 23 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6622-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6622-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6622-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'openssl' package(s) announced via the USN-6622-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"David Benjamin discovered that OpenSSL incorrectly handled excessively long
X9.42 DH keys. A remote attacker could possibly use this issue to cause
OpenSSL to consume resources, leading to a denial of service.
(CVE-2023-5678)

Sverker Eriksson discovered that OpenSSL incorrectly handled POLY1304 MAC
on the PowerPC architecture. A remote attacker could use this issue to
cause OpenSSL to crash, resulting in a denial of service, or possibly
execute arbitrary code. This issue only affected Ubuntu 22.04 LTS and
Ubuntu 23.04. (CVE-2023-6129)

It was discovered that OpenSSL incorrectly handled excessively long RSA
public keys. A remote attacker could possibly use this issue to cause
OpenSSL to consume resources, leading to a denial of service. This issue
only affected Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2023-6237)

Bahaa Naamneh discovered that OpenSSL incorrectly handled certain malformed
PKCS12 files. A remote attacker could possibly use this issue to cause
OpenSSL to crash, resulting in a denial of service. (CVE-2024-0727)");

  script_tag(name:"affected", value:"'openssl' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssl1.1", ver:"1.1.1f-1ubuntu2.21", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.2-0ubuntu1.14", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.10-1ubuntu2.2", rls:"UBUNTU23.10"))) {
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

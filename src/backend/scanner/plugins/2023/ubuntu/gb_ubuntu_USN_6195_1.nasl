# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6195.1");
  script_cve_id("CVE-2022-0128", "CVE-2022-0156", "CVE-2022-0158", "CVE-2022-0393", "CVE-2022-0407", "CVE-2022-0696");
  script_tag(name:"creation_date", value:"2023-07-04 04:07:42 +0000 (Tue, 04 Jul 2023)");
  script_version("2023-07-05T05:06:18+0000");
  script_tag(name:"last_modification", value:"2023-07-05 05:06:18 +0000 (Wed, 05 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-02-04 18:57:00 +0000 (Fri, 04 Feb 2022)");

  script_name("Ubuntu: Security Advisory (USN-6195-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6195-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6195-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the USN-6195-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Vim contained an out-of-bounds read vulnerability.
An attacker could possibly use this issue to cause a denial of service or
execute arbitrary code. (CVE-2022-0128)

It was discovered that Vim did not properly manage memory when freeing
allocated memory. An attacker could possibly use this issue to cause a
denial of service or execute arbitrary code. (CVE-2022-0156)

It was discovered that Vim contained a heap-based buffer overflow
vulnerability. An attacker could possibly use this issue to cause a denial
of service or execute arbitrary code. (CVE-2022-0158)

It was discovered that Vim did not properly manage memory when recording
and using select mode. An attacker could possibly use this issue to cause
a denial of service. (CVE-2022-0393)

It was discovered that Vim incorrectly handled certain memory operations
during a visual block yank. An attacker could possibly use this issue to
cause a denial of service or execute arbitrary code. (CVE-2022-0407)

It was discovered that Vim contained a NULL pointer dereference
vulnerability when switching tabpages. An attacker could possible use this
issue to cause a denial of service. (CVE-2022-0696)");

  script_tag(name:"affected", value:"'vim' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"vim", ver:"2:8.2.3995-1ubuntu2.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-athena", ver:"2:8.2.3995-1ubuntu2.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-gtk3", ver:"2:8.2.3995-1ubuntu2.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-nox", ver:"2:8.2.3995-1ubuntu2.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"vim-tiny", ver:"2:8.2.3995-1ubuntu2.9", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xxd", ver:"2:8.2.3995-1ubuntu2.9", rls:"UBUNTU22.04 LTS"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6320.1");
  script_cve_id("CVE-2023-4573", "CVE-2023-4574", "CVE-2023-4575", "CVE-2023-4577", "CVE-2023-4578", "CVE-2023-4579", "CVE-2023-4580", "CVE-2023-4581", "CVE-2023-4583", "CVE-2023-4584", "CVE-2023-4585");
  script_tag(name:"creation_date", value:"2023-08-31 06:20:34 +0000 (Thu, 31 Aug 2023)");
  script_version("2023-09-18T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-09-18 05:06:12 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-14 03:45:00 +0000 (Thu, 14 Sep 2023)");

  script_name("Ubuntu: Security Advisory (USN-6320-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6320-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6320-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6320-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Firefox. If a user were
tricked into opening a specially crafted website, an attacker could
potentially exploit these to cause a denial of service, obtain sensitive
information across domains, or execute arbitrary code. (CVE-2023-4573,
CVE-2023-4574, CVE-2023-4575, CVE-2023-4578, CVE-2023-4581, CVE-2023-4583,
CVE-2023-4584, CVE-2023-4585)

Lukas Bernhard discovered that Firefox did not properly manage memory when
the 'UpdateRegExpStatics' attempted to access 'initialStringHeap'. An
attacker could potentially exploit this issue to cause a denial of service.
(CVE-2023-4577)

Malte Jurgens discovered that Firefox did not properly handle search
queries if the search query itself was a well formed URL. An attacker could
potentially exploit this issue to perform spoofing attacks. (CVE-2023-4579)

Harveer Singh discovered that Firefox did not properly handle push
notifications stored on disk in private browsing mode. An attacker could
potentially exploits this issue to access sensitive information.
(CVE-2023-4580)");

  script_tag(name:"affected", value:"'firefox' package(s) on Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"117.0+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

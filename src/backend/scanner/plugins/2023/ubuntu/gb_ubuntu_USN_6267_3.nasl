# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6267.3");
  script_cve_id("CVE-2023-4045", "CVE-2023-4046", "CVE-2023-4047", "CVE-2023-4048", "CVE-2023-4049", "CVE-2023-4050", "CVE-2023-4051", "CVE-2023-4053", "CVE-2023-4055", "CVE-2023-4056", "CVE-2023-4057", "CVE-2023-4058");
  script_tag(name:"creation_date", value:"2023-08-21 09:16:49 +0000 (Mon, 21 Aug 2023)");
  script_version("2023-08-22T05:06:00+0000");
  script_tag(name:"last_modification", value:"2023-08-22 05:06:00 +0000 (Tue, 22 Aug 2023)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 17:50:00 +0000 (Fri, 04 Aug 2023)");

  script_name("Ubuntu: Security Advisory (USN-6267-3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6267-3");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6267-3");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2032143");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'firefox' package(s) announced via the USN-6267-3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6267-1 fixed vulnerabilities and USN-6267-2 fixed minor regressions in
Firefox. The update introduced several minor regressions. This update fixes
the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple security issues were discovered in Firefox. If a user were
 tricked into opening a specially crafted website, an attacker could
 potentially exploit these to cause a denial of service, obtain sensitive
 information across domains, or execute arbitrary code. (CVE-2023-4047,
 CVE-2023-4048, CVE-2023-4049, CVE-2023-4051, CVE-2023-4053, CVE-2023-4055,
 CVE-2023-4056, CVE-2023-4057, CVE-2023-4058)

 Max Vlasov discovered that Firefox Offscreen Canvas did not properly track
 cross-origin tainting. An attacker could potentially exploit this issue to
 access image data from another site in violation of same-origin policy.
 (CVE-2023-4045)

 Alexander Guryanov discovered that Firefox did not properly update the
 value of a global variable in WASM JIT analysis in some circumstances. An
 attacker could potentially exploit this issue to cause a denial of service.
 (CVE-2023-4046)

 Mark Brand discovered that Firefox did not properly validate the size of
 an untrusted input stream. An attacker could potentially exploit this issue
 to cause a denial of service. (CVE-2023-4050)");

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

  if(!isnull(res = isdpkgvuln(pkg:"firefox", ver:"116.0.3+build2-0ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

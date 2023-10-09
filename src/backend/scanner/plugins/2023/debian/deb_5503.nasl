# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5503");
  script_cve_id("CVE-2021-31439", "CVE-2022-0194", "CVE-2022-23121", "CVE-2022-23122", "CVE-2022-23123", "CVE-2022-23124", "CVE-2022-23125", "CVE-2022-43634", "CVE-2022-45188", "CVE-2023-42464");
  script_tag(name:"creation_date", value:"2023-09-21 04:19:37 +0000 (Thu, 21 Sep 2023)");
  script_version("2023-09-25T05:05:21+0000");
  script_tag(name:"last_modification", value:"2023-09-25 05:05:21 +0000 (Mon, 25 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-22 18:33:00 +0000 (Fri, 22 Sep 2023)");

  script_name("Debian: Security Advisory (DSA-5503)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5503");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5503");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5503");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/netatalk");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'netatalk' package(s) announced via the DSA-5503 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple security issues were discovered in Netatalk, an implementation of the Apple Filing Protocol (AFP) for offering file service (mainly) to macOS clients, which may result in the execution of arbitrary code or information disclosure.

For the oldstable distribution (bullseye), these problems have been fixed in version 3.1.12~ds-8+deb11u1.

We recommend that you upgrade your netatalk packages.

For the detailed security status of netatalk please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'netatalk' package(s) on Debian 11.");

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

if(release == "DEB11") {

  if(!isnull(res = isdpkgvuln(pkg:"netatalk", ver:"3.1.12~ds-8+deb11u1", rls:"DEB11"))) {
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

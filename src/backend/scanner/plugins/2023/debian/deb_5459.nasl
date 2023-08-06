# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5459");
  script_cve_id("CVE-2023-20593");
  script_tag(name:"creation_date", value:"2023-07-27 04:25:08 +0000 (Thu, 27 Jul 2023)");
  script_version("2023-08-03T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-08-03 05:05:16 +0000 (Thu, 03 Aug 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-01 19:29:00 +0000 (Tue, 01 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5459)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5459");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5459");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5459");
  script_xref(name:"URL", value:"https://lock.cmpxchg8b.com/zenbleed.html");
  script_xref(name:"URL", value:"https://github.com/google/security-research/security/advisories/GHSA-v6wh-rxpg-cmm8");
  script_xref(name:"URL", value:"https://www.amd.com/en/resources/product-security/bulletin/amd-sb-7008.html");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/amd64-microcode");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'amd64-microcode' package(s) announced via the DSA-5459 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tavis Ormandy discovered that under specific microarchitectural circumstances, a vector register in Zen 2 CPUs may not be written to 0 correctly. This flaw allows an attacker to leak register contents across concurrent processes, hyper threads and virtualized guests.

For details please refer to [link moved to references] [link moved to references]

The initial microcode release by AMD only provides updates for second generation EPYC CPUs: Various Ryzen CPUs are also affected, but no updates are available yet. Fixes will be provided in a later update once they are released.

For more specific details and target dates please refer to the AMD advisory at [link moved to references]

For the oldstable distribution (bullseye), this problem has been fixed in version 3.20230719.1~deb11u1. Additionally the update contains a fix for CVE-2019-9836.

For the stable distribution (bookworm), this problem has been fixed in version 3.20230719.1~deb12u1.

We recommend that you upgrade your amd64-microcode packages.

For the detailed security status of amd64-microcode please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'amd64-microcode' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"amd64-microcode", ver:"3.20230719.1~deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"amd64-microcode", ver:"3.20230719.1~deb12u1", rls:"DEB12"))) {
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

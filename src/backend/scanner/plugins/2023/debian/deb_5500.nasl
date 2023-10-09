# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5500");
  script_cve_id("CVE-2020-22219");
  script_tag(name:"creation_date", value:"2023-09-19 04:20:04 +0000 (Tue, 19 Sep 2023)");
  script_version("2023-09-19T05:06:02+0000");
  script_tag(name:"last_modification", value:"2023-09-19 05:06:02 +0000 (Tue, 19 Sep 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-30 16:57:00 +0000 (Wed, 30 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5500)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5500");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5500");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5500");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/flac");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'flac' package(s) announced via the DSA-5500 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"A buffer overflow was discovered in flac, a library handling Free Lossless Audio Codec media, which could potentially result in the execution of arbitrary code.

For the oldstable distribution (bullseye), this problem has been fixed in version 1.3.3-2+deb11u2.

We recommend that you upgrade your flac packages.

For the detailed security status of flac please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'flac' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"flac", ver:"1.3.3-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflac++-dev", ver:"1.3.3-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflac++6v5", ver:"1.3.3-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflac-dev", ver:"1.3.3-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflac-doc", ver:"1.3.3-2+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libflac8", ver:"1.3.3-2+deb11u2", rls:"DEB11"))) {
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

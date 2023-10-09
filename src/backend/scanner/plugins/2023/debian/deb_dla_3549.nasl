# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3549");
  script_cve_id("CVE-2021-37706", "CVE-2021-43299", "CVE-2021-43300", "CVE-2021-43301", "CVE-2021-43302", "CVE-2021-43303", "CVE-2021-43804", "CVE-2021-43845", "CVE-2022-21722", "CVE-2022-21723", "CVE-2022-23537", "CVE-2022-23547", "CVE-2022-23608", "CVE-2022-24754", "CVE-2022-24763", "CVE-2022-24764", "CVE-2022-24793", "CVE-2022-31031", "CVE-2022-39244", "CVE-2023-27585");
  script_tag(name:"creation_date", value:"2023-08-31 04:20:48 +0000 (Thu, 31 Aug 2023)");
  script_version("2023-08-31T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-08-31 05:05:25 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 17:36:00 +0000 (Fri, 07 Oct 2022)");

  script_name("Debian: Security Advisory (DLA-3549)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3549");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3549");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ring");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ring' package(s) announced via the DLA-3549 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several issue have been found in ring/jami, a secure and distributed voice, video and chat platform. The issues are about missing boundary checks, resulting in out-of-bound read access, buffer overflow or denial-of-service.

For Debian 10 buster, these problems have been fixed in version 20190215.1.f152c98~ds1-1+deb10u2.

We recommend that you upgrade your ring/jami packages.

For the detailed security status of ring please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ring' package(s) on Debian 10.");

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

if(release == "DEB10") {

  if(!isnull(res = isdpkgvuln(pkg:"jami", ver:"20190215.1.f152c98~ds1-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jami-daemon", ver:"20190215.1.f152c98~ds1-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ring", ver:"20190215.1.f152c98~ds1-1+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ring-daemon", ver:"20190215.1.f152c98~ds1-1+deb10u2", rls:"DEB10"))) {
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

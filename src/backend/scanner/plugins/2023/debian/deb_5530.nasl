# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5530");
  script_cve_id("CVE-2022-30122", "CVE-2022-30123", "CVE-2022-44570", "CVE-2022-44571", "CVE-2022-44572", "CVE-2023-27530", "CVE-2023-27539");
  script_tag(name:"creation_date", value:"2023-10-23 04:24:23 +0000 (Mon, 23 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-07 04:38:59 +0000 (Wed, 07 Dec 2022)");

  script_name("Debian: Security Advisory (DSA-5530-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5530-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5530-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5530");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ruby-rack");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ruby-rack' package(s) announced via the DSA-5530-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities were discovered in ruby-rack, a modular Ruby webserver interface, which may result in denial of service and shell escape sequence injection.

For the oldstable distribution (bullseye), these problems have been fixed in version 2.1.4-3+deb11u1.

We recommend that you upgrade your ruby-rack packages.

For the detailed security status of ruby-rack please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'ruby-rack' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"ruby-rack", ver:"2.1.4-3+deb11u1", rls:"DEB11"))) {
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

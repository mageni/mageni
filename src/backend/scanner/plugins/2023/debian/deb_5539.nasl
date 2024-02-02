# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5539");
  script_cve_id("CVE-2023-46234");
  script_tag(name:"creation_date", value:"2023-10-31 04:23:14 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:C/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-07 19:57:50 +0000 (Tue, 07 Nov 2023)");

  script_name("Debian: Security Advisory (DSA-5539-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5539-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5539-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5539");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-browserify-sign");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-browserify-sign' package(s) announced via the DSA-5539-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was reported that incorrect bound checks in the dsaVerify function in node-browserify-sign, a Node.js library which adds crypto signing for browsers, allows an attacker to perform signature forgery attacks by constructing signatures that can be successfully verified by any public key.

For the oldstable distribution (bullseye), this problem has been fixed in version 4.2.1-1+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 4.2.1-3+deb12u1.

We recommend that you upgrade your node-browserify-sign packages.

For the detailed security status of node-browserify-sign please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'node-browserify-sign' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-browserify-sign", ver:"4.2.1-1+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"node-browserify-sign", ver:"4.2.1-3+deb12u1", rls:"DEB12"))) {
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

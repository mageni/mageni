# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5431");
  script_cve_id("CVE-2023-32307");
  script_tag(name:"creation_date", value:"2023-06-19 04:39:02 +0000 (Mon, 19 Jun 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-06-08 15:30:00 +0000 (Thu, 08 Jun 2023)");

  script_name("Debian: Security Advisory (DSA-5431)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB11");

  script_xref(name:"Advisory-ID", value:"DSA-5431");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5431");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5431");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/sofia-sip");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'sofia-sip' package(s) announced via the DSA-5431 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Xu Biang discovered that missing input sanitising in Sofia-SIP, a SIP User-Agent library could result in denial of service.

For the oldstable distribution (bullseye), this problem has been fixed in version 1.12.11+20110422.1-2.1+deb11u2.

We recommend that you upgrade your sofia-sip packages.

For the detailed security status of sofia-sip please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'sofia-sip' package(s) on Debian 11.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-dev", ver:"1.12.11+20110422.1-2.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-glib-dev", ver:"1.12.11+20110422.1-2.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua-glib3", ver:"1.12.11+20110422.1-2.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libsofia-sip-ua0", ver:"1.12.11+20110422.1-2.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sofia-sip-bin", ver:"1.12.11+20110422.1-2.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sofia-sip-doc", ver:"1.12.11+20110422.1-2.1+deb11u2", rls:"DEB11"))) {
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

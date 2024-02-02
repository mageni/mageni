# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3663");
  script_cve_id("CVE-2023-41913");
  script_tag(name:"creation_date", value:"2023-11-27 04:28:29 +0000 (Mon, 27 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-12 17:07:01 +0000 (Tue, 12 Dec 2023)");

  script_name("Debian: Security Advisory (DLA-3663-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3663-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3663-1");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'strongswan' package(s) announced via the DLA-3663-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that there was a potential buffer overflow in strongswan, a IPsec-based VPN (Virtual Private Network) server.

A vulnerability related to processing public Diffie-Hellman key exchange values could have resulted in a buffer overflow and potentially remote code execution as a result.

CVE-2023-41913

A vulnerability in charon-tkm related to processing DH public values was discovered in strongSwan that can result in a buffer overflow and potentially remote code execution. All versions since 5.3.0 are affected.

For Debian 10 Buster, this problem has been fixed in version 5.7.2-1+deb10u4.

We recommend that you upgrade your strongswan packages.

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'strongswan' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"charon-cmd", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"charon-systemd", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libcharon-extra-plugins", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-extra-plugins", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libstrongswan-standard-plugins", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-charon", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-libcharon", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-nm", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-pki", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-scepclient", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-starter", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"strongswan-swanctl", ver:"5.7.2-1+deb10u4", rls:"DEB10"))) {
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

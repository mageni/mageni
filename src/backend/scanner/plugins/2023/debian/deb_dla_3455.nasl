# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3455");
  script_cve_id("CVE-2019-11840", "CVE-2019-11841", "CVE-2020-9283");
  script_tag(name:"creation_date", value:"2023-06-19 04:39:02 +0000 (Mon, 19 Jun 2023)");
  script_version("2023-06-20T05:05:25+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:25 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-11-18 23:15:00 +0000 (Wed, 18 Nov 2020)");

  script_name("Debian: Security Advisory (DLA-3455)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3455");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3455");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/golang-go.crypto");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'golang-go.crypto' package(s) announced via the DLA-3455 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in golang-go.crypto, the supplementary Go cryptography libraries.

CVE-2019-11840

An issue was discovered in supplementary Go cryptography libraries, aka golang-googlecode-go-crypto. If more than 256 GiB of keystream is generated, or if the counter otherwise grows greater than 32 bits, the amd64 implementation will first generate incorrect output, and then cycle back to previously generated keystream. Repeated keystream bytes can lead to loss of confidentiality in encryption applications, or to predictability in CSPRNG applications.

CVE-2019-11841

A message-forgery issue was discovered in crypto/openpgp/clearsign/clearsign.go in supplementary Go cryptography libraries. The Hash Armor Header specifies the message digest algorithm(s) used for the signature. Since the library skips Armor Header parsing in general, an attacker can not only embed arbitrary Armor Headers, but also prepend arbitrary text to cleartext messages without invalidating the signatures.

CVE-2020-9283

golang.org/x/crypto allows a panic during signature verification in the golang.org/x/crypto/ssh package. A client can attack an SSH server that accepts public keys. Also, a server can attack any SSH client.

The following Go packages have been rebuilt in order to fix the aforementioned issues.

rclone: 1.45-3+deb10u1 obfs4proxy: 0.0.7-4+deb10u1 gobuster: 2.0.1-1+deb10u1 restic: 0.9.4+ds-2+deb10u1 gopass: 1.2.0-2+deb10u1 aptly: 1.3.0+ds1-2.2~deb10u2 dnscrypt-proxy: 2.0.19+ds1-2+deb10u1 g10k: 0.5.7-1+deb10u1 hub: 2.7.0~ds1-1+deb10u1 acmetool: 0.0.62-3+deb10u1 syncthing: 1.0.0~ds1-1+deb10u1 packer: 1.3.4+dfsg-4+deb10u1 etcd: 3.2.26+dfsg-3+deb10u1 notary: 0.6.1~ds1-3+deb10u1

For Debian 10 buster, these problems have been fixed in version 1:0.0~git20181203.505ab14-1+deb10u1.

We recommend that you upgrade your golang-go.crypto packages.

For the detailed security status of golang-go.crypto please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'golang-go.crypto' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"golang-golang-x-crypto-dev", ver:"1:0.0~git20181203.505ab14-1+deb10u1", rls:"DEB10"))) {
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

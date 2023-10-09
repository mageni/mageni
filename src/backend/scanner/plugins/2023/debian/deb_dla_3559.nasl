# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3559");
  script_cve_id("CVE-2019-13115", "CVE-2019-17498", "CVE-2020-22218");
  script_tag(name:"creation_date", value:"2023-09-11 04:19:40 +0000 (Mon, 11 Sep 2023)");
  script_version("2023-09-11T05:05:16+0000");
  script_tag(name:"last_modification", value:"2023-09-11 05:05:16 +0000 (Mon, 11 Sep 2023)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-10-14 17:29:00 +0000 (Wed, 14 Oct 2020)");

  script_name("Debian: Security Advisory (DLA-3559)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3559");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/dla-3559");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/libssh2");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'libssh2' package(s) announced via the DLA-3559 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vulnerabilities were found in libssh2, a client-side C library implementing the SSH2 protocol, which could lead to denial of service or remote information disclosure.

CVE-2019-13115

Kevin Backhouse discovered an integer overflow vulnerability in kex.c's kex_method_diffie_hellman_group_exchange_sha256_key_exchange() function, which could lead to an out-of-bounds read in the way packets are read from the server. A remote attacker who compromises an SSH server may be able to disclose sensitive information or cause a denial of service condition on the client system when a user connects to the server.

CVE-2019-17498

Kevin Backhouse discovered that the SSH_MSG_DISCONNECT logic in packet.c has an integer overflow in a bounds check, thereby enabling an attacker to specify an arbitrary (out-of-bounds) offset for a subsequent memory read. A malicious SSH server may be able to disclose sensitive information or cause a denial of service condition on the client system when a user connects to the server.

CVE-2020-22218

An issue was discovered in function _libssh2_packet_add(), which could allow attackers to access out of bounds memory.

For Debian 10 buster, these problems have been fixed in version 1.8.0-2.1+deb10u1.

We recommend that you upgrade your libssh2 packages.

For the detailed security status of libssh2 please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'libssh2' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1", ver:"1.8.0-2.1+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssh2-1-dev", ver:"1.8.0-2.1+deb10u1", rls:"DEB10"))) {
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

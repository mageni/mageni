# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5532");
  script_cve_id("CVE-2023-5363");
  script_tag(name:"creation_date", value:"2023-10-25 14:01:56 +0000 (Wed, 25 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-09 13:55:32 +0000 (Thu, 09 Nov 2023)");

  script_name("Debian: Security Advisory (DSA-5532-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5532-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5532-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5532");
  script_xref(name:"URL", value:"https://www.openssl.org/news/secadv/20231024.txt");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssl");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssl' package(s) announced via the DSA-5532-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Tony Battersby reported that incorrect cipher key and IV length processing in OpenSSL, a Secure Sockets Layer toolkit, may result in loss of confidentiality for some symmetric cipher modes.

Additional details can be found in the upstream advisory: [link moved to references]

For the stable distribution (bookworm), this problem has been fixed in version 3.0.11-1~deb12u2.

We recommend that you upgrade your openssl packages.

For the detailed security status of openssl please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssl' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libcrypto3-udeb", ver:"3.0.11-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-dev", ver:"3.0.11-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl-doc", ver:"3.0.11-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl3", ver:"3.0.11-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libssl3-udeb", ver:"3.0.11-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssl", ver:"3.0.11-1~deb12u2", rls:"DEB12"))) {
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

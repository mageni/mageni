# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5586");
  script_cve_id("CVE-2023-48795", "CVE-2023-51385");
  script_tag(name:"creation_date", value:"2023-12-25 04:20:13 +0000 (Mon, 25 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-03 19:40:07 +0000 (Wed, 03 Jan 2024)");

  script_name("Debian: Security Advisory (DSA-5586-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5586-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5586-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5586");
  script_xref(name:"URL", value:"https://terrapin-attack.com/");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/openssh");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'openssh' package(s) announced via the DSA-5586-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several vulnerabilities have been discovered in OpenSSH, an implementation of the SSH protocol suite.

CVE-2021-41617

It was discovered that sshd failed to correctly initialise supplemental groups when executing an AuthorizedKeysCommand or AuthorizedPrincipalsCommand, where a AuthorizedKeysCommandUser or AuthorizedPrincipalsCommandUser directive has been set to run the command as a different user. Instead these commands would inherit the groups that sshd was started with.

CVE-2023-28531

Luci Stanescu reported that a error prevented constraints being communicated to the ssh-agent when adding smartcard keys to the agent with per-hop destination constraints, resulting in keys being added without constraints.

CVE-2023-48795

Fabian Baeumer, Marcus Brinkmann and Joerg Schwenk discovered that the SSH protocol is prone to a prefix truncation attack, known as the Terrapin attack. This attack allows a MITM attacker to effect a limited break of the integrity of the early encrypted SSH transport protocol by sending extra messages prior to the commencement of encryption, and deleting an equal number of consecutive messages immediately after encryption starts.

Details can be found at [link moved to references]

CVE-2023-51384

It was discovered that when PKCS#11-hosted private keys were added while specifying destination constraints, if the PKCS#11 token returned multiple keys then only the first key had the constraints applied.

CVE-2023-51385

It was discovered that if an invalid user or hostname that contained shell metacharacters was passed to ssh, and a ProxyCommand, LocalCommand directive or match exec predicate referenced the user or hostname via expansion tokens, then an attacker who could supply arbitrary user/hostnames to ssh could potentially perform command injection. The situation could arise in case of git repositories with submodules, where the repository could contain a submodule with shell characters in its user or hostname.

For the oldstable distribution (bullseye), these problems have been fixed in version 1:8.4p1-5+deb11u3.

For the stable distribution (bookworm), these problems have been fixed in version 1:9.2p1-2+deb12u2.

We recommend that you upgrade your openssh packages.

For the detailed security status of openssh please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'openssh' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-tests", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:8.4p1-5+deb11u3", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-client-udeb", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-server-udeb", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-sftp-server", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"openssh-tests", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ssh-askpass-gnome", ver:"1:9.2p1-2+deb12u2", rls:"DEB12"))) {
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

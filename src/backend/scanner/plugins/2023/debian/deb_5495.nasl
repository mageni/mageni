# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5495");
  script_cve_id("CVE-2023-31490", "CVE-2023-38802", "CVE-2023-41358");
  script_tag(name:"creation_date", value:"2023-09-12 04:19:33 +0000 (Tue, 12 Sep 2023)");
  script_version("2023-09-12T05:05:19+0000");
  script_tag(name:"last_modification", value:"2023-09-12 05:05:19 +0000 (Tue, 12 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-30 00:44:00 +0000 (Wed, 30 Aug 2023)");

  script_name("Debian: Security Advisory (DSA-5495)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5495");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5495");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5495");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/frr");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'frr' package(s) announced via the DSA-5495 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilities were discovered in frr, the FRRouting suite of internet protocols, while processing malformed requests and packets the BGP daemon may have reachable assertions, NULL pointer dereference, out-of-bounds memory access, which may lead to denial of service attack.

For the oldstable distribution (bullseye), these problems have been fixed in version 7.5.1-1.1+deb11u2.

For the stable distribution (bookworm), these problems have been fixed in version 8.4.4-1.1~deb12u1.

We recommend that you upgrade your frr packages.

For the detailed security status of frr please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'frr' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"frr", ver:"7.5.1-1.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-doc", ver:"7.5.1-1.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-pythontools", ver:"7.5.1-1.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-rpki-rtrlib", ver:"7.5.1-1.1+deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-snmp", ver:"7.5.1-1.1+deb11u2", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"frr", ver:"8.4.4-1.1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-doc", ver:"8.4.4-1.1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-pythontools", ver:"8.4.4-1.1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-rpki-rtrlib", ver:"8.4.4-1.1~deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"frr-snmp", ver:"8.4.4-1.1~deb12u1", rls:"DEB12"))) {
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

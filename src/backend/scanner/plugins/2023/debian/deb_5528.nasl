# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5528");
  script_cve_id("CVE-2023-45133");
  script_tag(name:"creation_date", value:"2023-10-17 04:20:07 +0000 (Tue, 17 Oct 2023)");
  script_version("2023-10-17T05:05:34+0000");
  script_tag(name:"last_modification", value:"2023-10-17 05:05:34 +0000 (Tue, 17 Oct 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5528)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5528");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5528");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5528");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/node-babel7");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'node-babel7' package(s) announced via the DSA-5528 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"William Khem-Marquez discovered that using malicious plugins for the the Babel JavaScript compiler could result in arbitrary code execution during compilation

For the oldstable distribution (bullseye), this problem has been fixed in version 7.12.12+~cs150.141.84-6+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 7.20.15+ds1+~cs214.269.168-3+deb12u1.

We recommend that you upgrade your node-babel7 packages.

For the detailed security status of node-babel7 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'node-babel7' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7", ver:"7.12.12+~cs150.141.84-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7-runtime", ver:"7.12.12+~cs150.141.84-6+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7-standalone", ver:"7.12.12+~cs150.141.84-6+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7", ver:"7.20.15+ds1+~cs214.269.168-3+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7-debug", ver:"7.20.15+ds1+~cs214.269.168-3+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7-runtime", ver:"7.20.15+ds1+~cs214.269.168-3+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-babel7-standalone", ver:"7.20.15+ds1+~cs214.269.168-3+deb12u1", rls:"DEB12"))) {
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

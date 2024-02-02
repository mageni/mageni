# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3682");
  script_cve_id("CVE-2021-39537", "CVE-2023-29491");
  script_tag(name:"creation_date", value:"2023-12-04 04:22:47 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-10-02 02:14:20 +0000 (Sat, 02 Oct 2021)");

  script_name("Debian: Security Advisory (DLA-3682-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3682-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3682-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/ncurses");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'ncurses' package(s) announced via the DLA-3682-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Issues were found in ncurses, a collection of shared libraries for terminal handling, which could lead to denial of service.

CVE-2021-39537

It has been discovered that the tic(1) utility is susceptible to a heap overflow on crafted input due to improper bounds checking.

CVE-2023-29491

Jonathan Bar Or, Michael Pearse and Emanuele Cozzi have discovered that when ncurses is used by a setuid application, a local user can trigger security-relevant memory corruption via malformed data in a terminfo database file found in $HOME/.terminfo or reached via the TERMINFO or TERM environment variables.

In order to mitigate this issue, ncurses now further restricts programs running with elevated privileges (setuid/setgid programs). Programs run by the superuser remain able to load custom terminfo entries.

This change aligns ncurses' behavior in buster-security with that of Debian Bullseye's latest point release (6.2+20201114-2+deb11u2).

For Debian 10 buster, these problems have been fixed in version 6.1+20181013-2+deb10u5.

We recommend that you upgrade your ncurses packages.

For the detailed security status of ncurses please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'ncurses' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncurses-dev", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncurses6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32ncursesw6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib32tinfo6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ncurses-dev", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ncurses6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64ncursesw6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"lib64tinfo6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses-dev", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses5", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses5-dev", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncurses6-dbg", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncursesw5", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncursesw5-dev", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncursesw6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libncursesw6-dbg", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo-dev", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo5", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo6", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo6-dbg", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libtinfo6-udeb", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-base", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-bin", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-doc", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-examples", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ncurses-term", ver:"6.1+20181013-2+deb10u5", rls:"DEB10"))) {
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

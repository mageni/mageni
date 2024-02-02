# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5564");
  script_cve_id("CVE-2023-44441", "CVE-2023-44442", "CVE-2023-44443", "CVE-2023-44444");
  script_tag(name:"creation_date", value:"2023-11-27 04:28:29 +0000 (Mon, 27 Nov 2023)");
  script_version("2024-01-12T16:12:11+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:11 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5564-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5564-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/DSA-5564-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5564");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gimp");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gimp' package(s) announced via the DSA-5564-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Michael Randrianantenaina reported several vulnerabilities in GIMP, the GNU Image Manipulation Program, which could result in denial of service (application crash) or potentially the execution of arbitrary code if malformed DDS, PSD and PSP files are opened.

For the oldstable distribution (bullseye), these problems have been fixed in version 2.10.22-4+deb11u1.

For the stable distribution (bookworm), these problems have been fixed in version 2.10.34-1+deb12u1.

We recommend that you upgrade your gimp packages.

For the detailed security status of gimp please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gimp' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.10.22-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gimp-data", ver:"2.10.22-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.10.22-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.10.22-4+deb11u1", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.10.22-4+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"gimp", ver:"2.10.34-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gimp-data", ver:"2.10.34-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0", ver:"2.10.34-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0-dev", ver:"2.10.34-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libgimp2.0-doc", ver:"2.10.34-1+deb12u1", rls:"DEB12"))) {
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

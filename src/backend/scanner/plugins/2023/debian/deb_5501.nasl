# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5501");
  script_cve_id("CVE-2023-43090");
  script_tag(name:"creation_date", value:"2023-09-19 04:20:04 +0000 (Tue, 19 Sep 2023)");
  script_version("2023-09-29T16:09:25+0000");
  script_tag(name:"last_modification", value:"2023-09-29 16:09:25 +0000 (Fri, 29 Sep 2023)");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-26 13:10:00 +0000 (Tue, 26 Sep 2023)");

  script_name("Debian: Security Advisory (DSA-5501)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5501");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5501");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5501");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/gnome-shell");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'gnome-shell' package(s) announced via the DSA-5501 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mickael Karatekin discovered that the GNOME session locking didn't restrict a keyboard shortcut used for taking screenshots in GNOME Screenshot which could result in information disclosure.

The oldstable distribution (bullseye) is not affected.

For the stable distribution (bookworm), this problem has been fixed in version 43.6-1~deb12u2.

We recommend that you upgrade your gnome-shell packages.

For the detailed security status of gnome-shell please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'gnome-shell' package(s) on Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"gnome-shell", ver:"43.6-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnome-shell-common", ver:"43.6-1~deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"gnome-shell-extension-prefs", ver:"43.6-1~deb12u2", rls:"DEB12"))) {
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

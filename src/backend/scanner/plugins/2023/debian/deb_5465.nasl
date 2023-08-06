# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5465");
  script_cve_id("CVE-2023-36053");
  script_tag(name:"creation_date", value:"2023-08-04 04:22:52 +0000 (Fri, 04 Aug 2023)");
  script_version("2023-08-04T05:06:23+0000");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 14:26:00 +0000 (Tue, 11 Jul 2023)");

  script_name("Debian: Security Advisory (DSA-5465)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5465");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5465");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5465");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/python-django");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'python-django' package(s) announced via the DSA-5465 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Seokchan Yoon discovered that missing sanitising in the email and URL validators of Django, a Python web development framework, could result in denial of service.

For the oldstable distribution (bullseye), this problem has been fixed in version 2:2.2.28-1~deb11u2. This update also addresses CVE-2023-23969, CVE-2023-31047 and CVE-2023-24580.

For the stable distribution (bookworm), this problem has been fixed in version 3:3.2.19-1+deb12u1.

We recommend that you upgrade your python-django packages.

For the detailed security status of python-django please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'python-django' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"2:2.2.28-1~deb11u2", rls:"DEB11"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"2:2.2.28-1~deb11u2", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python-django-doc", ver:"3:3.2.19-1+deb12u1", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-django", ver:"3:3.2.19-1+deb12u1", rls:"DEB12"))) {
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

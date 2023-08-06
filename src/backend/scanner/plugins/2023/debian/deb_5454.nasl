# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5454");
  script_cve_id("CVE-2023-36813");
  script_tag(name:"creation_date", value:"2023-07-18 04:28:45 +0000 (Tue, 18 Jul 2023)");
  script_version("2023-07-18T05:05:36+0000");
  script_tag(name:"last_modification", value:"2023-07-18 05:05:36 +0000 (Tue, 18 Jul 2023)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-12 16:17:00 +0000 (Wed, 12 Jul 2023)");

  script_name("Debian: Security Advisory (DSA-5454)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5454");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5454");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5454");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/kanboard");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'kanboard' package(s) announced via the DSA-5454 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Riccardo Bonafede discovered that the Kanboard project management software was susceptible to SQL injection.

For the stable distribution (bookworm), this problem has been fixed in version 1.2.26+ds-2+deb12u2.

We recommend that you upgrade your kanboard packages.

For the detailed security status of kanboard please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'kanboard' package(s) on Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"kanboard", ver:"1.2.26+ds-2+deb12u2", rls:"DEB12"))) {
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

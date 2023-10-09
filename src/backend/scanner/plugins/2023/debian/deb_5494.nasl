# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5494");
  script_cve_id("CVE-2023-4874", "CVE-2023-4875");
  script_tag(name:"creation_date", value:"2023-09-11 04:19:40 +0000 (Mon, 11 Sep 2023)");
  script_version("2023-09-18T05:06:12+0000");
  script_tag(name:"last_modification", value:"2023-09-18 05:06:12 +0000 (Mon, 18 Sep 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-13 14:30:00 +0000 (Wed, 13 Sep 2023)");

  script_name("Debian: Security Advisory (DSA-5494)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5494");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5494");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5494");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/mutt");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'mutt' package(s) announced via the DSA-5494 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several NULL pointer dereference flaws were discovered in Mutt, a text-based mailreader supporting MIME, GPG, PGP and threading, which may result in denial of service (application crash) when viewing a specially crafted email or when composing from a specially crafted draft message.

For the oldstable distribution (bullseye), these problems have been fixed in version 2.0.5-4.1+deb11u3.

For the stable distribution (bookworm), these problems have been fixed in version 2.2.9-1+deb12u1.

We recommend that you upgrade your mutt packages.

For the detailed security status of mutt please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'mutt' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mutt", ver:"2.0.5-4.1+deb11u3", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mutt", ver:"2.2.9-1+deb12u1", rls:"DEB12"))) {
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

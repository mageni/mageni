# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3681");
  script_cve_id("CVE-2022-37703", "CVE-2022-37705", "CVE-2023-30577");
  script_tag(name:"creation_date", value:"2023-12-04 04:22:47 +0000 (Mon, 04 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-08-04 15:21:45 +0000 (Fri, 04 Aug 2023)");

  script_name("Debian: Security Advisory (DLA-3681-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3681-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3681-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/amanda");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'amanda' package(s) announced via the DLA-3681-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Multiple vulnerabilties have been found in Amanda,a backup system designed to archive many computers on a network to a single large-capacity tape drive. The vulnerabilties potentially allows local privilege escalation from the backup user to root or leak information whether a directory exists in the filesystem.

CVE-2022-37703

In Amanda 3.5.1, an information leak vulnerability was found in the calcsize SUID binary. An attacker can abuse this vulnerability to know if a directory exists or not anywhere in the fs. The binary will use `opendir()` as root directly without checking the path, letting the attacker provide an arbitrary path.


CVE-2022-37705

A privilege escalation flaw was found in Amanda 3.5.1 in which the backup user can acquire root privileges. The vulnerable component is the runtar SUID program, which is a wrapper to run /usr/bin/tar with specific arguments that are controllable by the attacker. This program mishandles the arguments passed to tar binary.

CVE-2023-30577

The SUID binary runtar can accept the possibly malicious GNU tar options if fed with some non-argument option starting with '--exclude' (say --exclude-vcs). The following option will be accepted as good and it could be an option passing some script/binary that would be executed with root permissions.

For Debian 10 buster, these problems have been fixed in version 1:3.5.1-2+deb10u2.

We recommend that you upgrade your amanda packages.

For the detailed security status of amanda please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'amanda' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"amanda-client", ver:"1:3.5.1-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"amanda-common", ver:"1:3.5.1-2+deb10u2", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"amanda-server", ver:"1:3.5.1-2+deb10u2", rls:"DEB10"))) {
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

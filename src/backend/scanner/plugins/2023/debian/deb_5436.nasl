# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2023.5436");
  script_cve_id("CVE-2023-1183");
  script_tag(name:"creation_date", value:"2023-06-22 04:33:16 +0000 (Thu, 22 Jun 2023)");
  script_version("2023-06-22T10:34:14+0000");
  script_tag(name:"last_modification", value:"2023-06-22 10:34:14 +0000 (Thu, 22 Jun 2023)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DSA-5436)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB(11|12)");

  script_xref(name:"Advisory-ID", value:"DSA-5436");
  script_xref(name:"URL", value:"https://www.debian.org/security/2023/dsa-5436");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/DSA-5436");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/hsqldb1.8.0");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'hsqldb1.8.0' package(s) announced via the DSA-5436 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Gregor Kopf of Secfault Security GmbH discovered that HSQLDB, a Java SQL database engine, allowed the execution of spurious scripting commands in .script and .log files. Hsqldb supports a SCRIPT keyword which is normally used to record the commands input by the database admin to output such a script. In combination with LibreOffice, an attacker could craft an odb containing a 'database/script' file which itself contained a SCRIPT command where the contents of the file could be written to a new file whose location was determined by the attacker.

For the oldstable distribution (bullseye), this problem has been fixed in version 1.8.0.10+dfsg-10+deb11u1.

For the stable distribution (bookworm), this problem has been fixed in version 1.8.0.10+dfsg-11+deb12u1.

We recommend that you upgrade your hsqldb1.8.0 packages.

For the detailed security status of hsqldb1.8.0 please refer to its security tracker page at: [link moved to references]");

  script_tag(name:"affected", value:"'hsqldb1.8.0' package(s) on Debian 11, Debian 12.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libhsqldb1.8.0-java", ver:"1.8.0.10+dfsg-10+deb11u1", rls:"DEB11"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libhsqldb1.8.0-java", ver:"1.8.0.10+dfsg-11+deb12u1", rls:"DEB12"))) {
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

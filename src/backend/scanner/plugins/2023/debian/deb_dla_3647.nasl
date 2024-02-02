# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3647");
  script_tag(name:"creation_date", value:"2023-11-08 04:19:52 +0000 (Wed, 08 Nov 2023)");
  script_version("2024-01-12T16:12:12+0000");
  script_tag(name:"last_modification", value:"2024-01-12 16:12:12 +0000 (Fri, 12 Jan 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("Debian: Security Advisory (DLA-3647-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3647-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3647-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/trapperkeeper-webserver-jetty9-clojure");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'trapperkeeper-webserver-jetty9-clojure' package(s) announced via the DLA-3647-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The recent update of jetty9, released as DLA 3641-1, caused a regression in PuppetDB, a major component of Puppet that helps you manage and automate the configuration of servers. More specifically another package, trapperkeeperwebserver-jetty9-clojure, still used the deprecated SslContextFactory class which made PuppetDB fail to start. This update makes use of the preferred new SslContextFactory#Server class now.

For Debian 10 buster, this problem has been fixed in version 1.7.0-2+deb10u2.

We recommend that you upgrade your trapperkeeper-webserver-jetty9-clojure packages.

For the detailed security status of trapperkeeper-webserver-jetty9-clojure please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'trapperkeeper-webserver-jetty9-clojure' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libtrapperkeeper-webserver-jetty9-clojure", ver:"1.7.0-2+deb10u2", rls:"DEB10"))) {
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

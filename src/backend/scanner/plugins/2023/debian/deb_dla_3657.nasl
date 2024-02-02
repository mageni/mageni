# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.2.2023.3657");
  script_cve_id("CVE-2020-13920", "CVE-2021-26117", "CVE-2023-46604");
  script_tag(name:"creation_date", value:"2023-11-21 04:21:40 +0000 (Tue, 21 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-08 14:28:20 +0000 (Wed, 08 Nov 2023)");

  script_name("Debian: Security Advisory (DLA-3657-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB10");

  script_xref(name:"Advisory-ID", value:"DLA-3657-1");
  script_xref(name:"URL", value:"https://www.debian.org/lts/security/2023/DLA-3657-1");
  script_xref(name:"URL", value:"https://security-tracker.debian.org/tracker/activemq");
  script_xref(name:"URL", value:"https://wiki.debian.org/LTS");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'activemq' package(s) announced via the DLA-3657-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Several security vulnerabilities have been discovered in ActiveMQ, a Java message broker.

CVE-2020-13920

Apache ActiveMQ uses LocateRegistry.createRegistry() to create the JMX RMI registry and binds the server to the jmxrmi entry. It is possible to connect to the registry without authentication and call the rebind method to rebind jmxrmi to something else. If an attacker creates another server to proxy the original, and bound that, he effectively becomes a man in the middle and is able to intercept the credentials when an user connects.

CVE-2021-26117

The optional ActiveMQ LDAP login module can be configured to use anonymous access to the LDAP server.

CVE-2023-46604

The Java OpenWire protocol marshaller is vulnerable to Remote Code Execution. This vulnerability may allow a remote attacker with network access to either a Java-based OpenWire broker or client to run arbitrary shell commands by manipulating serialized class types in the OpenWire protocol to cause either the client or the broker (respectively) to instantiate any class on the classpath.

For Debian 10 buster, these problems have been fixed in version 5.15.16-0+deb10u1.

We recommend that you upgrade your activemq packages.

For the detailed security status of activemq please refer to its security tracker page at: [link moved to references]

Further information about Debian LTS security advisories, how to apply these updates to your system and frequently asked questions can be found at: [link moved to references]");

  script_tag(name:"affected", value:"'activemq' package(s) on Debian 10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"activemq", ver:"5.15.16-0+deb10u1", rls:"DEB10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libactivemq-java", ver:"5.15.16-0+deb10u1", rls:"DEB10"))) {
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

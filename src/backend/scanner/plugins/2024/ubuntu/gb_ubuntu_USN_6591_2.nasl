# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6591.2");
  script_cve_id("CVE-2023-51764");
  script_tag(name:"creation_date", value:"2024-02-01 04:09:34 +0000 (Thu, 01 Feb 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-05 16:19:53 +0000 (Fri, 05 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6591-2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS|22\.04\ LTS|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6591-2");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6591-2");
  script_xref(name:"URL", value:"https://www.postfix.org/smtp-smuggling.html");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/postfix/+bug/2049337");
  script_xref(name:"URL", value:"https://bugs.launchpad.net/ubuntu/+source/postfix/+bug/2050834");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'postfix' package(s) announced via the USN-6591-2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6591-1 fixed vulnerabilities in Postfix. A fix with less risk of
regression has been made available since the last update. This update
updates the fix and aligns with the latest configuration guidelines
regarding this vulnerability.

We apologize for the inconvenience.

Original advisory details:

 Timo Longin discovered that Postfix incorrectly handled certain email line
 endings. A remote attacker could possibly use this issue to bypass an email
 authentication mechanism, allowing domain spoofing and potential spamming.

 Please note that certain configuration changes are required to address
 this issue. They are not enabled by default for backward compatibility.
 Information can be found at [link moved to references].");

  script_tag(name:"affected", value:"'postfix' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.10.");

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

if(release == "UBUNTU14.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"2.11.0-1ubuntu1.2+esm3", rls:"UBUNTU14.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"3.1.0-3ubuntu0.4+esm3", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"3.3.0-1ubuntu0.4+esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"3.4.13-0ubuntu1.4", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"3.6.4-1ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.10") {

  if(!isnull(res = isdpkgvuln(pkg:"postfix", ver:"3.8.1-2ubuntu0.2", rls:"UBUNTU23.10"))) {
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

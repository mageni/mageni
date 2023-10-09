# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6419.1");
  script_cve_id("CVE-2016-7103", "CVE-2021-41182", "CVE-2021-41183", "CVE-2021-41184", "CVE-2022-31160");
  script_tag(name:"creation_date", value:"2023-10-06 04:08:21 +0000 (Fri, 06 Oct 2023)");
  script_version("2023-10-06T05:06:29+0000");
  script_tag(name:"last_modification", value:"2023-10-06 05:06:29 +0000 (Fri, 06 Oct 2023)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-27 14:46:00 +0000 (Wed, 27 Jul 2022)");

  script_name("Ubuntu: Security Advisory (USN-6419-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(14\.04\ LTS|16\.04\ LTS|18\.04\ LTS|20\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6419-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6419-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'jqueryui' package(s) announced via the USN-6419-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hong Phat Ly discovered that jQuery UI did not properly manage parameters
from untrusted sources, which could lead to arbitrary web script or HTML
code injection. A remote attacker could possibly use this issue to perform
a cross-site scripting (XSS) attack. This issue only affected
Ubuntu 14.04 LTS and Ubuntu 16.04 LTS. (CVE-2016-7103)

Esben Sparre Andreasen discovered that jQuery UI did not properly handle
values from untrusted sources in the Datepicker widget. A remote attacker
could possibly use this issue to perform a cross-site scripting (XSS)
attack and execute arbitrary code. This issue only affected
Ubuntu 14.04 LTS, Ubuntu 16.04 LTS, Ubuntu 18.04 LTS, and Ubuntu 20.04 LTS.
(CVE-2021-41182, CVE-2021-41183)

It was discovered that jQuery UI did not properly validate values from
untrusted sources. An attacker could possibly use this issue to cause a
denial of service or execute arbitrary code. This issue only affected
Ubuntu 20.04 LTS. (CVE-2021-41184)

It was discovered that the jQuery UI checkboxradio widget did not properly
decode certain values from HTML entities. An attacker could possibly use
this issue to perform a cross-site scripting (XSS) attack and cause a
denial of service or execute arbitrary code. This issue only affected
Ubuntu 20.04 LTS. (CVE-2022-31160)");

  script_tag(name:"affected", value:"'jqueryui' package(s) on Ubuntu 14.04, Ubuntu 16.04, Ubuntu 18.04, Ubuntu 20.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-ui", ver:"1.10.1+dfsg-1ubuntu0.14.04.1~esm1", rls:"UBUNTU14.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-ui", ver:"1.10.1+dfsg-1ubuntu0.16.04.1~esm1", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-ui", ver:"1.12.1+dfsg-5ubuntu0.18.04.1~esm3", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-jquery-ui", ver:"1.12.1+dfsg-5ubuntu0.18.04.1~esm3", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libjs-jquery-ui", ver:"1.12.1+dfsg-5ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"node-jquery-ui", ver:"1.12.1+dfsg-5ubuntu0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

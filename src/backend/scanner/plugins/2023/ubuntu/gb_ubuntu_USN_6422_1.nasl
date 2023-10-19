# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6422.1");
  script_cve_id("CVE-2021-37706", "CVE-2021-43299", "CVE-2021-43300", "CVE-2021-43301", "CVE-2021-43302", "CVE-2021-43303", "CVE-2021-43804", "CVE-2021-43845", "CVE-2022-21722", "CVE-2022-21723", "CVE-2022-23537", "CVE-2022-23547", "CVE-2022-23608", "CVE-2022-24754", "CVE-2022-24763", "CVE-2022-24764", "CVE-2022-24793", "CVE-2022-31031", "CVE-2022-39244", "CVE-2023-27585");
  script_tag(name:"creation_date", value:"2023-10-10 04:08:37 +0000 (Tue, 10 Oct 2023)");
  script_version("2023-10-10T05:05:41+0000");
  script_tag(name:"last_modification", value:"2023-10-10 05:05:41 +0000 (Tue, 10 Oct 2023)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-10-07 17:36:00 +0000 (Fri, 07 Oct 2022)");

  script_name("Ubuntu: Security Advisory (USN-6422-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(18\.04\ LTS|20\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6422-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6422-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ring' package(s) announced via the USN-6422-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Ring incorrectly handled certain inputs. If a user or
an automated system were tricked into opening a specially crafted input file,
a remote attacker could possibly use this issue to execute arbitrary code.
(CVE-2021-37706)

It was discovered that Ring incorrectly handled certain inputs. If a user or
an automated system were tricked into opening a specially crafted input file,
a remote attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 18.04 LTS and Ubuntu 20.04 LTS.
(CVE-2021-43299, CVE-2021-43300, CVE-2021-43301, CVE-2021-43302,
CVE-2021-43303, CVE-2021-43804, CVE-2021-43845, CVE-2022-21723,
CVE-2022-23537, CVE-2022-23547, CVE-2022-23608, CVE-2022-24754,
CVE-2022-24763, CVE-2022-24764, CVE-2022-24793, CVE-2022-31031,
CVE-2022-39244)

It was discovered that Ring incorrectly handled certain inputs. If a user or
an automated system were tricked into opening a specially crafted input file,
a remote attacker could possibly use this issue to cause a denial of service.
This issue only affected Ubuntu 20.04 LTS. (CVE-2022-21722)

It was discovered that Ring incorrectly handled certain inputs. If a user or
an automated system were tricked into opening a specially crafted input file,
a remote attacker could possibly use this issue to cause a denial of service.
(CVE-2023-27585)");

  script_tag(name:"affected", value:"'ring' package(s) on Ubuntu 18.04, Ubuntu 20.04, Ubuntu 23.04.");

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

if(release == "UBUNTU18.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"ring", ver:"20180228.1.503da2b~ds1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ring-daemon", ver:"20180228.1.503da2b~ds1-1ubuntu0.1~esm1", rls:"UBUNTU18.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"jami", ver:"20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jami-daemon", ver:"20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ring", ver:"20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"ring-daemon", ver:"20190215.1.f152c98~ds1-1+deb10u2build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU23.04") {

  if(!isnull(res = isdpkgvuln(pkg:"jami", ver:"20230206.0~ds1-5ubuntu0.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"jami-daemon", ver:"20230206.0~ds1-5ubuntu0.1", rls:"UBUNTU23.04"))) {
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

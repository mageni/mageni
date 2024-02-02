# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6447.1");
  script_cve_id("CVE-2020-36130", "CVE-2020-36131", "CVE-2020-36133", "CVE-2020-36135", "CVE-2021-30473", "CVE-2021-30474", "CVE-2021-30475");
  script_tag(name:"creation_date", value:"2023-10-24 04:08:28 +0000 (Tue, 24 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2021-06-11 13:57:00 +0000 (Fri, 11 Jun 2021)");

  script_name("Ubuntu: Security Advisory (USN-6447-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU20\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6447-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6447-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'aom' package(s) announced via the USN-6447-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that AOM incorrectly handled certain inputs. If a user or an
automated system were tricked into opening a specially crafted input file, a
remote attacker could possibly use this issue to cause a denial of service.
(CVE-2020-36130, CVE-2020-36131, CVE-2020-36133, CVE-2020-36135,
CVE-2021-30473, CVE-2021-30474, CVE-2021-30475)");

  script_tag(name:"affected", value:"'aom' package(s) on Ubuntu 20.04.");

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

if(release == "UBUNTU20.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"aom-tools", ver:"1.0.0.errata1-3+deb11u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaom-dev", ver:"1.0.0.errata1-3+deb11u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaom-doc", ver:"1.0.0.errata1-3+deb11u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libaom0", ver:"1.0.0.errata1-3+deb11u1build0.20.04.1", rls:"UBUNTU20.04 LTS"))) {
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

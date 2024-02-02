# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6564.1");
  script_cve_id("CVE-2022-4304", "CVE-2022-4450", "CVE-2023-0215", "CVE-2023-0286", "CVE-2023-0401");
  script_tag(name:"creation_date", value:"2024-01-04 04:08:55 +0000 (Thu, 04 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-02-18 21:48:41 +0000 (Sat, 18 Feb 2023)");

  script_name("Ubuntu: Security Advisory (USN-6564-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU22\.04\ LTS");

  script_xref(name:"Advisory-ID", value:"USN-6564-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6564-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'nodejs' package(s) announced via the USN-6564-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Hubert Kario discovered that Node.js incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to obtain sensitive
information. (CVE-2022-4304)

CarpetFuzz, Dawei Wang discovered that Node.js incorrectly handled certain
inputs. If a user or an automated system were tricked into opening a specially
crafted input file, a remote attacker could possibly use this issue to cause a
denial of service. (CVE-2022-4450)

Octavio Galland and Marcel Bohme discovered that Node.js incorrectly handled
certain inputs. If a user or an automated system were tricked into opening a
specially crafted input file, a remote attacker could possibly use this issue
to cause a denial of service. (CVE-2023-0215)

David Benjamin discovered that Node.js incorrectly handled certain inputs. If a
user or an automated system were tricked into opening a specially crafted input
file, a remote attacker could possibly use this issue to obtain sensitive
information. (CVE-2023-0286)

Hubert Kario and Dmitry Belyavsky discovered that Node.js incorrectly handled
certain inputs. If a user or an automated system were tricked into opening a
specially crafted input file, a remote attacker could possibly use this issue
to cause a denial of service. (CVE-2023-0401)");

  script_tag(name:"affected", value:"'nodejs' package(s) on Ubuntu 22.04.");

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

if(release == "UBUNTU22.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"libnode-dev", ver:"12.22.9~dfsg-1ubuntu3.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libnode72", ver:"12.22.9~dfsg-1ubuntu3.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"nodejs", ver:"12.22.9~dfsg-1ubuntu3.3", rls:"UBUNTU22.04 LTS"))) {
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

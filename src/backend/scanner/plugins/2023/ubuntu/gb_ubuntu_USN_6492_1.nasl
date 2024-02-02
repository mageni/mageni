# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6492.1");
  script_cve_id("CVE-2021-34431", "CVE-2021-34434", "CVE-2021-41039", "CVE-2023-0809", "CVE-2023-28366", "CVE-2023-3592");
  script_tag(name:"creation_date", value:"2023-11-22 04:08:57 +0000 (Wed, 22 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-04 17:00:37 +0000 (Wed, 04 Oct 2023)");

  script_name("Ubuntu: Security Advisory (USN-6492-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6492-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6492-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'mosquitto' package(s) announced via the USN-6492-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Kathrin Kleinhammer discovered that Mosquitto incorrectly handled certain
inputs. If a user or an automated system were provided with a specially crafted
input, a remote attacker could possibly use this issue to cause a denial of
service. This issue only affected Ubuntu 20.04 LTS. (CVE-2021-34431)

Zhanxiang Song discovered that Mosquitto incorrectly handled certain inputs. If
a user or an automated system were provided with a specially crafted input, a
remote attacker could possibly use this issue to cause an authorisation bypass.
This issue only affected Ubuntu 22.04 LTS and Ubuntu 23.04. (CVE-2021-34434)

Zhanxiang Song, Bin Yuan, DeQing Zou, and Hai Jin discovered that Mosquitto
incorrectly handled certain inputs. If a user or an automated system were
provided with a specially crafted input, a remote attacker could possibly use
this issue to cause a denial of service. This issue only affected Ubuntu 20.04
LTS and Ubuntu 22.04 LTS. (CVE-2021-41039)

Zhengjie Du discovered that Mosquitto incorrectly handled certain inputs. If a
user or an automated system were provided with a specially crafted input file,
a remote attacker could possibly use this issue to cause a denial of service.
(CVE-2023-0809)

It was discovered that Mosquitto incorrectly handled certain inputs. If a user
or an automated system were provided with a specially crafted input, a remote
attacker could possibly use this issue to cause a denial of service.
(CVE-2023-3592)

Mischa Bachmann discovered that Mosquitto incorrectly handled certain inputs.
If a user or an automated system were provided with a specially crafted input,
a remote attacker could possibly use this issue to cause a denial of service.
This issue was only fixed in Ubuntu 22.04 LTS and Ubuntu 23.04.
(CVE-2023-28366)");

  script_tag(name:"affected", value:"'mosquitto' package(s) on Ubuntu 20.04, Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"1.6.9-1ubuntu0.1~esm1", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"2.0.11-1ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"mosquitto", ver:"2.0.11-1.2ubuntu0.1", rls:"UBUNTU23.04"))) {
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

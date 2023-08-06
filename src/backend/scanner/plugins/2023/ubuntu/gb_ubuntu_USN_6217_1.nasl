# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6217.1");
  script_cve_id("CVE-2023-33170");
  script_tag(name:"creation_date", value:"2023-07-12 04:09:28 +0000 (Wed, 12 Jul 2023)");
  script_version("2023-07-13T05:06:09+0000");
  script_tag(name:"last_modification", value:"2023-07-13 05:06:09 +0000 (Thu, 13 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.6");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-07-11 18:15:00 +0000 (Tue, 11 Jul 2023)");

  script_name("Ubuntu: Security Advisory (USN-6217-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|22\.10|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6217-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6217-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet6, dotnet7' package(s) announced via the USN-6217-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"McKee-Harris, Matt Cotterell, and Jack Moran discovered that .NET did
not properly update account lockout maximum failed attempts. An
attacker could possibly use this issue to bypass the security feature
and attempt to guess more passwords for an account.");

  script_tag(name:"affected", value:"'dotnet6, dotnet7' package(s) on Ubuntu 22.04, Ubuntu 22.10, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.120-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.109-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.120-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.109-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.120-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.109-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.120-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.109-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.120-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.109-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.120-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.109-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "UBUNTU22.10") {

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.120-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.109-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.120-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.109-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.120-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.109-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.120-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.109-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.120-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.109-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.120-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.109-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.120-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.109-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.120-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.109-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.120-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.109-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.120-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.109-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.120-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.109-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.120-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.109-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
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

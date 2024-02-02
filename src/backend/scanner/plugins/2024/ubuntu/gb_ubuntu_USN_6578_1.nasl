# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6578.1");
  script_cve_id("CVE-2024-0057", "CVE-2024-21319");
  script_tag(name:"creation_date", value:"2024-01-12 04:09:10 +0000 (Fri, 12 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-16 18:47:36 +0000 (Tue, 16 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6578-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6578-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6578-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet6, dotnet7, dotnet8' package(s) announced via the USN-6578-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Vishal Mishra and Anita Gaud discovered that .NET did not properly
validate X.509 certificates with malformed signatures. An attacker
could possibly use this issue to bypass an application's typical
authentication logic.
(CVE-2024-0057)

Morgan Brown discovered that .NET did not properly handle requests from
unauthenticated clients. An attacker could possibly use this issue to
cause a denial of service.
(CVE-2024-21319)");

  script_tag(name:"affected", value:"'dotnet6, dotnet7, dotnet8' package(s) on Ubuntu 22.04, Ubuntu 23.04, Ubuntu 23.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.126-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.115-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.126-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.115-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.126-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.115-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.126-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.115-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.126-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.115-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.126-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.115-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.126-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.115-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.126-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.115-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.126-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.115-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.126-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.115-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.126-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.115-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.126-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.115-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.126-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.115-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-8.0", ver:"8.0.1-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.126-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.115-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-8.0", ver:"8.0.1-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.126-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.115-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-8.0", ver:"8.0.1-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.126-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.115-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-8.0", ver:"8.0.1-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.126-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.115-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-8.0", ver:"8.0.101-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.126-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.115-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet8", ver:"8.0.101-8.0.1-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6480.1");
  script_cve_id("CVE-2023-36049", "CVE-2023-36558");
  script_tag(name:"creation_date", value:"2023-11-16 04:08:48 +0000 (Thu, 16 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-11-21 19:25:39 +0000 (Tue, 21 Nov 2023)");

  script_name("Ubuntu: Security Advisory (USN-6480-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04|23\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6480-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6480-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet6, dotnet7, dotnet8' package(s) announced via the USN-6480-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Barry Dorrans discovered that .NET did not properly implement certain
security features for Blazor server forms. An attacker could possibly
use this issue to bypass validation, which could trigger unintended
actions. (CVE-2023-36558)

Piotr Bazydlo discovered that .NET did not properly handle untrusted
URIs provided to System.Net.WebRequest.Create. An attacker could possibly
use this issue to inject arbitrary commands to backend FTP servers.
(CVE-2023-36049)");

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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.125-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.114-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.125-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.114-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.125-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.114-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.125-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.114-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.125-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.114-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.125-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.114-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.125-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.114-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.125-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.114-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.125-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.114-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.125-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.114-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.125-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.114-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.125-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.114-0ubuntu1~23.04.1", rls:"UBUNTU23.04"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.125-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.114-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-8.0", ver:"8.0.0-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.125-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.114-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-8.0", ver:"8.0.0-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.125-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.114-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-8.0", ver:"8.0.0-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.125-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.114-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-8.0", ver:"8.0.0-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.125-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.114-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-8.0", ver:"8.0.100-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.125-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.114-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet8", ver:"8.0.100-8.0.0-0ubuntu1~23.10.1", rls:"UBUNTU23.10"))) {
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

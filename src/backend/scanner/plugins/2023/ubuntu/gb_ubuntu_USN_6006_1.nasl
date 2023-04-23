# Copyright (C) 2023 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6006.1");
  script_cve_id("CVE-2023-28260");
  script_tag(name:"creation_date", value:"2023-04-13 04:09:11 +0000 (Thu, 13 Apr 2023)");
  script_version("2023-04-13T10:09:33+0000");
  script_tag(name:"last_modification", value:"2023-04-13 10:09:33 +0000 (Thu, 13 Apr 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-11 21:15:00 +0000 (Tue, 11 Apr 2023)");

  script_name("Ubuntu: Security Advisory (USN-6006-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone Networks GmbH");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|22\.10)");

  script_xref(name:"Advisory-ID", value:"USN-6006-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6006-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'dotnet6, dotnet7' package(s) announced via the USN-6006-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that .NET did not properly manage dll files. An
attacker could potentially use this issue to execute arbitrary code.");

  script_tag(name:"affected", value:"'dotnet6, dotnet7' package(s) on Ubuntu 22.04, Ubuntu 22.10.");

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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.116-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.116-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.116-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.116-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.116-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.116-0ubuntu1~22.04.1", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-6.0", ver:"6.0.116-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"aspnetcore-runtime-7.0", ver:"7.0.105-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host-7.0", ver:"7.0.105-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-host", ver:"6.0.116-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-6.0", ver:"6.0.116-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-hostfxr-7.0", ver:"7.0.105-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-6.0", ver:"6.0.116-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-runtime-7.0", ver:"7.0.105-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-6.0", ver:"6.0.116-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet-sdk-7.0", ver:"7.0.105-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet6", ver:"6.0.116-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"dotnet7", ver:"7.0.105-0ubuntu1~22.10.1", rls:"UBUNTU22.10"))) {
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

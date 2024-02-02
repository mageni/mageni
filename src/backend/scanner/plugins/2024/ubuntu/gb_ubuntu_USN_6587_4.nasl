# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2024.6587.4");
  script_cve_id("CVE-2023-6816", "CVE-2024-0229", "CVE-2024-0408", "CVE-2024-0409", "CVE-2024-21885", "CVE-2024-21886");
  script_tag(name:"creation_date", value:"2024-02-02 04:09:01 +0000 (Fri, 02 Feb 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-01-26 18:50:40 +0000 (Fri, 26 Jan 2024)");

  script_name("Ubuntu: Security Advisory (USN-6587-4)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(16\.04\ LTS|18\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6587-4");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6587-4");
  script_xref(name:"URL", value:"https://launchpad.net/bugs/2051536");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'xorg-server' package(s) announced via the USN-6587-4 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"USN-6587-1 fixed vulnerabilities in X.Org X Server. The fix was incomplete
resulting in a possible regression. This update fixes the problem.

Original advisory details:

 Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
 memory when processing the DeviceFocusEvent and ProcXIQueryPointer APIs. An
 attacker could possibly use this issue to cause the X Server to crash,
 obtain sensitive information, or execute arbitrary code. (CVE-2023-6816)

 Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
 reattaching to a different master device. An attacker could use this issue
 to cause the X Server to crash, leading to a denial of service, or possibly
 execute arbitrary code. (CVE-2024-0229)

 Olivier Fourdan and Donn Seeley discovered that the X.Org X Server
 incorrectly labeled GLX PBuffers when used with SELinux. An attacker could
 use this issue to cause the X Server to crash, leading to a denial of
 service. (CVE-2024-0408)

 Olivier Fourdan discovered that the X.Org X Server incorrectly handled
 the curser code when used with SELinux. An attacker could use this issue to
 cause the X Server to crash, leading to a denial of service.
 (CVE-2024-0409)

 Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
 memory when processing the XISendDeviceHierarchyEvent API. An attacker
 could possibly use this issue to cause the X Server to crash, or execute
 arbitrary code. (CVE-2024-21885)

 Jan-Niklas Sohn discovered that the X.Org X Server incorrectly handled
 devices being disabled. An attacker could possibly use this issue to cause
 the X Server to crash, or execute arbitrary code. (CVE-2024-21886)");

  script_tag(name:"affected", value:"'xorg-server' package(s) on Ubuntu 16.04, Ubuntu 18.04.");

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

if(release == "UBUNTU16.04 LTS") {

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.18.4-0ubuntu0.12+esm10", rls:"UBUNTU16.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.18.4-0ubuntu0.12+esm10", rls:"UBUNTU16.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"xserver-xorg-core", ver:"2:1.19.6-1ubuntu4.15+esm5", rls:"UBUNTU18.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"xwayland", ver:"2:1.19.6-1ubuntu4.15+esm5", rls:"UBUNTU18.04 LTS"))) {
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

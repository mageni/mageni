# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6241.1");
  script_cve_id("CVE-2023-2088");
  script_tag(name:"creation_date", value:"2023-07-25 08:33:44 +0000 (Tue, 25 Jul 2023)");
  script_version("2023-07-26T05:05:08+0000");
  script_tag(name:"last_modification", value:"2023-07-26 05:05:08 +0000 (Wed, 26 Jul 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 18:00:00 +0000 (Fri, 26 May 2023)");

  script_name("Ubuntu: Security Advisory (USN-6241-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(22\.04\ LTS|23\.04)");

  script_xref(name:"Advisory-ID", value:"USN-6241-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6241-1");
  script_xref(name:"URL", value:"https://security.openstack.org/ossa/OSSA-2023-003.html");
  script_xref(name:"URL", value:"https://discourse.ubuntu.com/t/cve-2023-2088-for-charmed-openstack/37051");
  script_xref(name:"URL", value:"https://lists.openstack.org/pipermail/openstack-discuss/2023-July/034439.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'cinder, ironic, nova, python-glance-store, python-os-brick' package(s) announced via the USN-6241-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Jan Wasilewski and Gorka Eguileor discovered that OpenStack incorrectly
handled deleted volume attachments. An authenticated user or attacker could
possibly use this issue to gain access to sensitive information.

This update may require configuration changes, please see the upstream
advisory and the other links below for more information:

[link moved to references]
[link moved to references]
[link moved to references]");

  script_tag(name:"affected", value:"'cinder, ironic, nova, python-glance-store, python-os-brick' package(s) on Ubuntu 22.04, Ubuntu 23.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"python3-cinder", ver:"2:20.2.0-0ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-glance-store", ver:"3.0.0-0ubuntu1.3", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ironic", ver:"1:20.1.0-0ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-nova", ver:"3:25.1.1-0ubuntu1.1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-os-brick", ver:"5.2.2-0ubuntu1.2", rls:"UBUNTU22.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"python3-cinder", ver:"2:22.0.0-0ubuntu1.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-glance-store", ver:"4.3.0-0ubuntu1.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-ironic", ver:"1:21.4.0-0ubuntu1.1", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-nova", ver:"3:27.0.0-0ubuntu1.3", rls:"UBUNTU23.04"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"python3-os-brick", ver:"6.2.0-0ubuntu2.3", rls:"UBUNTU23.04"))) {
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

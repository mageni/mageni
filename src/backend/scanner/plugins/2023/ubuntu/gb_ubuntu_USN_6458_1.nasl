# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.12.2023.6458.1");
  script_cve_id("CVE-2022-29500", "CVE-2022-29501", "CVE-2022-29502");
  script_tag(name:"creation_date", value:"2023-10-31 04:08:37 +0000 (Tue, 31 Oct 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-05-13 04:20:39 +0000 (Fri, 13 May 2022)");

  script_name("Ubuntu: Security Advisory (USN-6458-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Ubuntu Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/ubuntu_linux", "ssh/login/packages", re:"ssh/login/release=UBUNTU(20\.04\ LTS|22\.04\ LTS)");

  script_xref(name:"Advisory-ID", value:"USN-6458-1");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6458-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'slurm-llnl, slurm-wlm' package(s) announced via the USN-6458-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"It was discovered that Slurm did not properly handle credential
management, which could allow an unprivileged user to impersonate the
SlurmUser account. An attacker could possibly use this issue to execute
arbitrary code as the root user. (CVE-2022-29500)

It was discovered that Slurm did not properly handle access control when
dealing with RPC traffic through PMI2 and PMIx, which could allow an
unprivileged user to send data to an arbitrary unix socket in the host.
An attacker could possibly use this issue to execute arbitrary code as
the root user. (CVE-2022-29501)

It was discovered that Slurm did not properly handle validation logic when
processing input and output data with the srun client, which could lead to
the interception of process I/O. An attacker could possibly use this issue
to expose sensitive information or execute arbitrary code. This issue only
affected Ubuntu 22.04 LTS. (CVE-2022-29502)");

  script_tag(name:"affected", value:"'slurm-llnl, slurm-wlm' package(s) on Ubuntu 20.04, Ubuntu 22.04.");

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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm34", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"19.05.5-1ubuntu0.1~esm2", rls:"UBUNTU20.04 LTS"))) {
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

  if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm37", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmrestd", ver:"21.08.5-2ubuntu1+esm1", rls:"UBUNTU22.04 LTS"))) {
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

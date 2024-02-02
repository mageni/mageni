# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.1.1.2024.5609");
  script_cve_id("CVE-2023-49933", "CVE-2023-49936", "CVE-2023-49937", "CVE-2023-49938");
  script_tag(name:"creation_date", value:"2024-01-29 04:19:07 +0000 (Mon, 29 Jan 2024)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"10.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-21 17:17:34 +0000 (Thu, 21 Dec 2023)");

  script_name("Debian: Security Advisory (DSA-5609-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Debian Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages", re:"ssh/login/release=DEB12");

  script_xref(name:"Advisory-ID", value:"DSA-5609-1");
  script_xref(name:"URL", value:"https://www.debian.org/security/2024/DSA-5609-1");

  script_tag(name:"summary", value:"The remote host is missing an update for the Debian 'slurm-wlm' package(s) announced via the DSA-5609-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"affected", value:"'slurm-wlm' package(s) on Debian 12.");

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

if(release == "DEB12") {

  if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpam-slurm-adopt", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi0", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi0-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libpmi2-0-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm-perl", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurm38", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"libslurmdb-perl", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-client-emulator", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-basic-plugins-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-doc", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-elasticsearch-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-elasticsearch-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-emulator", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-hdf5-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-hdf5-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-influxdb-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-influxdb-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-ipmi-plugins", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-ipmi-plugins-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-jwt-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-jwt-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-mysql-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-mysql-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-plugins", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-plugins-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-rrd-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-rrd-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-rsmi-plugin", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-rsmi-plugin-dev", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurm-wlm-torque", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmctld", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmd", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmdbd", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"slurmrestd", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
    report += res;
  }

  if(!isnull(res = isdpkgvuln(pkg:"sview", ver:"22.05.8-4+deb12u2", rls:"DEB12"))) {
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

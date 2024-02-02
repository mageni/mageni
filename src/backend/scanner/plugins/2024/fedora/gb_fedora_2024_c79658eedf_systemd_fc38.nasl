# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885626");
  script_version("2024-02-02T14:37:52+0000");
  script_cve_id("CVE-2023-7008");
  script_tag(name:"cvss_base", value:"5.4");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:N");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-23 13:15:07 +0000 (Sat, 23 Dec 2023)");
  script_tag(name:"creation_date", value:"2024-01-28 02:02:16 +0000 (Sun, 28 Jan 2024)");
  script_name("Fedora: Security Advisory for systemd (FEDORA-2024-c79658eedf)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-c79658eedf");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/4GMDEG5PKONWNHOEYSUDRT6JEOISRMN2");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'systemd'
  package(s) announced via the FEDORA-2024-c79658eedf advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"systemd is a system and service manager that runs as PID 1 and starts the rest
of the system. It provides aggressive parallelization capabilities, uses socket
and D-Bus activation for starting services, offers on-demand starting of
daemons, keeps track of processes using Linux control groups, maintains mount
and automount points, and implements an elaborate transactional dependency-based
service control logic. systemd supports SysV and LSB init scripts and works as a
replacement for sysvinit. Other parts of this package are a logging daemon,
utilities to control basic system configuration like the hostname, date, locale,
maintain a list of logged-in users, system accounts, runtime directories and
settings, and a logging daemons.

This package was built from the v253-stable branch of systemd.");

  script_tag(name:"affected", value:"'systemd' package(s) on Fedora 38.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release)
  exit(0);

res = "";
report = "";

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"systemd", rpm:"systemd~253.15~2.fc38", rls:"FC38"))) {
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
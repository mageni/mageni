# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827835");
  script_version("2023-06-21T05:06:23+0000");
  script_cve_id("CVE-2023-26555");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-21 05:06:23 +0000 (Wed, 21 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-06-14 01:10:46 +0000 (Wed, 14 Jun 2023)");
  script_name("Fedora: Security Advisory for ntp-refclock (FEDORA-2023-c0762a0e57)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-c0762a0e57");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/Y3VHEHHWCTYSB7HVJLYPVK4RPJZ5LX52");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'ntp-refclock'
  package(s) announced via the FEDORA-2023-c0762a0e57 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"ntp-refclock is a wrapper for reference clock drivers included in the ntpd
daemon, which enables other NTP implementations to use the supported hardware
reference clocks for synchronization of the system clock.

It provides a minimal environment for the drivers to be able to run in a
separate process, measuring the offset of the system clock relative to the
reference clock and sending the measurements to another process controlling
the system clock.");

  script_tag(name:"affected", value:"'ntp-refclock' package(s) on Fedora 37.");

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

if(release == "FC37") {

  if(!isnull(res = isrpmvuln(pkg:"ntp-refclock", rpm:"ntp-refclock~0.6~1.fc37", rls:"FC37"))) {
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
# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885310");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2022-24599");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-03-03 16:29:00 +0000 (Thu, 03 Mar 2022)");
  script_tag(name:"creation_date", value:"2023-11-22 02:16:36 +0000 (Wed, 22 Nov 2023)");
  script_name("Fedora: Security Advisory for audiofile (FEDORA-2023-e23e432cb2)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-e23e432cb2");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WTETOUJNRR75REYJZTBGF6TAJZYTMXUY");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'audiofile'
  package(s) announced via the FEDORA-2023-e23e432cb2 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The Audio File library is an implementation of the Audio File Library
from SGI, which provides an API for accessing audio file formats like
AIFF/AIFF-C, WAVE, and NeXT/Sun .snd/.au files. This library is used
by the EsounD daemon.

Install audiofile if you are installing EsounD or you need an API for
any of the sound file formats it can handle.");

  script_tag(name:"affected", value:"'audiofile' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"audiofile", rpm:"audiofile~0.3.6~36.fc37", rls:"FC37"))) {
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
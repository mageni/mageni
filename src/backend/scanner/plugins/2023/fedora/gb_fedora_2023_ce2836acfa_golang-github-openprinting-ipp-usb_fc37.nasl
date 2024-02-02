# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885364");
  script_version("2023-12-15T16:10:08+0000");
  script_cve_id("CVE-2022-41717");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-12-15 16:10:08 +0000 (Fri, 15 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-12-12 17:50:00 +0000 (Mon, 12 Dec 2022)");
  script_tag(name:"creation_date", value:"2023-12-02 02:14:30 +0000 (Sat, 02 Dec 2023)");
  script_name("Fedora: Security Advisory for golang-github-openprinting-ipp-usb (FEDORA-2023-ce2836acfa)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC37");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-ce2836acfa");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/CSVIS6MTMFVBA7JPMRAUNKUOYEVSJYSB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'golang-github-openprinting-ipp-usb'
  package(s) announced via the FEDORA-2023-ce2836acfa advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"HTTP reverse proxy, backed by IPP-over-USB connection to device. It enables
 driverless support for USB devices capable of using IPP-over-USB protocol.");

  script_tag(name:"affected", value:"'golang-github-openprinting-ipp-usb' package(s) on Fedora 37.");

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

  if(!isnull(res = isrpmvuln(pkg:"golang-github-openprinting-ipp-usb", rpm:"golang-github-openprinting-ipp-usb~0.9.23~5.fc37", rls:"FC37"))) {
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
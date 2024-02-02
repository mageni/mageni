# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0353");
  script_cve_id("CVE-2023-45866");
  script_tag(name:"creation_date", value:"2023-12-21 04:12:10 +0000 (Thu, 21 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.8");
  script_tag(name:"cvss_base_vector", value:"AV:A/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-18 18:41:29 +0000 (Mon, 18 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0353)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0353");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0353.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32604");
  script_xref(name:"URL", value:"https://github.com/skysafe/reblog/tree/main/cve-2023-45866");
  script_xref(name:"URL", value:"https://ubuntu.com/security/notices/USN-6540-1");
  script_xref(name:"URL", value:"https://git.kernel.org/pub/scm/bluetooth/bluez.git/commit/profiles/input?id=25a471a83e02e1effb15d5a488b3f0085eaeb675");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bluez' package(s) announced via the MGASA-2023-0353 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes the following security issue.
Bluetooth HID Hosts in BlueZ may permit an unauthenticated Peripheral
role HID Device to initiate and establish an encrypted connection, and
accept HID keyboard reports, potentially permitting injection of HID
messages when no user interaction has occurred in the Central role to
authorize such access (CVE-2023-45866).");

  script_tag(name:"affected", value:"'bluez' package(s) on Mageia 9.");

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

if(release == "MAGEIA9") {

  if(!isnull(res = isrpmvuln(pkg:"bluez", rpm:"bluez~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-cups", rpm:"bluez-cups~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-hid2hci", rpm:"bluez-hid2hci~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"bluez-mesh", rpm:"bluez-mesh~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez-devel", rpm:"lib64bluez-devel~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"lib64bluez3", rpm:"lib64bluez3~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez-devel", rpm:"libbluez-devel~5.70~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libbluez3", rpm:"libbluez3~5.70~1.mga9", rls:"MAGEIA9"))) {
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

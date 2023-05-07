# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884284");
  script_version("2023-04-27T12:17:38+0000");
  script_cve_id("CVE-2023-0547", "CVE-2023-1945", "CVE-2023-1999", "CVE-2023-28427", "CVE-2023-29479", "CVE-2023-29533", "CVE-2023-29535", "CVE-2023-29536", "CVE-2023-29539", "CVE-2023-29541", "CVE-2023-29548", "CVE-2023-29550");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-27 12:17:38 +0000 (Thu, 27 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-25 01:00:35 +0000 (Tue, 25 Apr 2023)");
  script_name("CentOS: Security Advisory for thunderbird (CESA-2023:1806)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:1806");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-April/086395.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2023:1806 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 102.10.0.

Security Fix(es):

  * Thunderbird: Revocation status of S/Mime recipient certificates was not
checked (CVE-2023-0547)

  * Mozilla: Matrix SDK bundled with Thunderbird vulnerable to
denial-of-service attack (CVE-2023-28427)

  * Mozilla: Fullscreen notification obscured (CVE-2023-29533)

  * Mozilla: Potential Memory Corruption following Garbage Collector
compaction (CVE-2023-29535)

  * Mozilla: Invalid free from JavaScript code (CVE-2023-29536)

  * Mozilla: Memory safety bugs fixed in Firefox 112 and Firefox ESR 102.10
(CVE-2023-29550)

  * Mozilla: Memory Corruption in Safe Browsing Code (CVE-2023-1945)

  * Thunderbird: Hang when processing certain OpenPGP messages
(CVE-2023-29479)

  * Mozilla: Content-Disposition filename truncation leads to Reflected File
Download (CVE-2023-29539)

  * Mozilla: Files with malicious extensions could have been downloaded
unsafely on Linux (CVE-2023-29541)

  * Mozilla: Incorrect optimization result on ARM64 (CVE-2023-29548)

  * Mozilla: Double-free in libwebp (CVE-2023-1999)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'thunderbird' package(s) on CentOS 7.");

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

if(release == "CentOS7") {

  if(!isnull(res = isrpmvuln(pkg:"thunderbird", rpm:"thunderbird~102.10.0~2.el7.centos", rls:"CentOS7"))) {
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
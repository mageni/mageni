# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0221");
  script_cve_id("CVE-2023-24055", "CVE-2023-32784");
  script_tag(name:"creation_date", value:"2023-07-10 04:12:52 +0000 (Mon, 10 Jul 2023)");
  script_version("2023-07-10T08:07:42+0000");
  script_tag(name:"last_modification", value:"2023-07-10 08:07:42 +0000 (Mon, 10 Jul 2023)");
  script_tag(name:"cvss_base", value:"7.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-26 16:25:00 +0000 (Fri, 26 May 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0221)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA8");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0221");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0221.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31935");
  script_xref(name:"URL", value:"https://amp.thehackernews.com/thn/2023/05/keepass-exploit-allows-attackers-to.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'keepass' package(s) announced via the MGASA-2023-0221 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Allows an attacker, who has write access to the XML configuration file, to
obtain the cleartext passwords by adding an export trigger. Disputed by
vendor due to level of access required. (CVE-2023-24055)
Possible to recover the cleartext master password from a memory dump, even
when a workspace is locked or no longer running (CVE-2023-32784)");

  script_tag(name:"affected", value:"'keepass' package(s) on Mageia 8.");

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

if(release == "MAGEIA8") {

  if(!isnull(res = isrpmvuln(pkg:"keepass", rpm:"keepass~2.54~1.mga8", rls:"MAGEIA8"))) {
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

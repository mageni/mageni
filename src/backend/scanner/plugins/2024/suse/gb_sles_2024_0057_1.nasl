# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0057.1");
  script_cve_id("CVE-2023-4759");
  script_tag(name:"creation_date", value:"2024-01-09 04:20:13 +0000 (Tue, 09 Jan 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-09-18 13:54:11 +0000 (Mon, 18 Sep 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0057-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2|SLES15\.0SP3)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0057-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240057-1/");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.9");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.8");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.7");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.6");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.5");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.4");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.3");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.2");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.1");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.2.0");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.71");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.70");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.69");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.68");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.67");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.66");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.65");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.64");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.63");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.62");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.61");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.60");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.59");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.58");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.57");
  script_xref(name:"URL", value:"https://github.com/mwiede/jsch/releases/tag/jsch-0.1.56");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'eclipse-jgit, jsch' package(s) announced via the SUSE-SU-2024:0057-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for eclipse-jgit, jsch fixes the following issues:
Security fix:
- CVE-2023-4759: Fixed an arbitrary file overwrite which might have occurred with a specially crafted git repository and a case-insensitive filesystem. (bsc#1215298)
Other fixes:
jsch was updated to version 0.2.9:
- Added support for various algorithms
- Migrated from com.jcraft:jsch to com.github.mwiede:jsch fork (bsc#1211955):
 * Alias to the old artifact since the new one is drop-in
 replacement
 * Keep the old OSGi bundle symbolic name to avoid extensive
 patching of eclipse stack
- Updated to version 0.2.9:
 * For the full list of changes please consult the upstream changelogs below for each version updated:
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references]
 + [link moved to references] eclipse-jgit:

Craft the jgit script from the real Main class of the jar file instead of using a jar launcher (bsc#1209646)");

  script_tag(name:"affected", value:"'eclipse-jgit, jsch' package(s) on SUSE Enterprise Storage 7.1, SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise High Performance Computing 15-SP3, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server 15-SP3, SUSE Linux Enterprise Server for SAP Applications 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP3, SUSE Manager Server 4.3.");

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

if(release == "SLES15.0SP2") {

  if(!isnull(res = isrpmvuln(pkg:"jsch", rpm:"jsch~0.2.9~150200.11.10.1", rls:"SLES15.0SP2"))) {
    report += res;
  }

  if(report != "") {
    security_message(data:report);
  } else if(__pkg_match) {
    exit(99);
  }
  exit(0);
}

if(release == "SLES15.0SP3") {

  if(!isnull(res = isrpmvuln(pkg:"jsch", rpm:"jsch~0.2.9~150200.11.10.1", rls:"SLES15.0SP3"))) {
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

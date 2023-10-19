# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.4097.1");
  script_cve_id("CVE-2023-1829");
  script_tag(name:"creation_date", value:"2023-10-18 06:37:15 +0000 (Wed, 18 Oct 2023)");
  script_version("2023-10-18T09:41:51+0000");
  script_tag(name:"last_modification", value:"2023-10-18 09:41:51 +0000 (Wed, 18 Oct 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-19 19:16:00 +0000 (Wed, 19 Apr 2023)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:4097-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES15\.0SP2)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:4097-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20234097-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'suse-module-tools' package(s) announced via the SUSE-SU-2023:4097-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for suse-module-tools fixes the following issues:


Updated to version 15.2.18:


CVE-2023-1829: Blacklisted the Linux kernel tcindex classifier
 module (bsc#1210335).

Blacklisted the Linux kernel RNDIS modules (bsc#1205767,
 jsc#PED-5731).
Fixed a build issue for s390x.");

  script_tag(name:"affected", value:"'suse-module-tools' package(s) on SUSE Linux Enterprise High Performance Computing 15-SP2, SUSE Linux Enterprise Server 15-SP2, SUSE Linux Enterprise Server for SAP Applications 15-SP2.");

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

  if(!isnull(res = isrpmvuln(pkg:"suse-module-tools", rpm:"suse-module-tools~15.2.18~150200.4.15.1", rls:"SLES15.0SP2"))) {
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

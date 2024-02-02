# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0307.1");
  script_cve_id("CVE-2023-40474");
  script_tag(name:"creation_date", value:"2024-02-02 04:20:27 +0000 (Fri, 02 Feb 2024)");
  script_version("2024-02-02T14:37:52+0000");
  script_tag(name:"last_modification", value:"2024-02-02 14:37:52 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0307-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0307-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240307-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gstreamer' package(s) announced via the SUSE-SU-2024:0307-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gstreamer fixes the following issues:

CVE-2023-40474: Fixed an integer overflow during MXF file parsing (bsc#1215796).");

  script_tag(name:"affected", value:"'gstreamer' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gstreamer", rpm:"gstreamer~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-debuginfo", rpm:"gstreamer-debuginfo~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-debuginfo-32bit", rpm:"gstreamer-debuginfo-32bit~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-debugsource", rpm:"gstreamer-debugsource~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-lang", rpm:"gstreamer-lang~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-utils", rpm:"gstreamer-utils~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gstreamer-utils-debuginfo", rpm:"gstreamer-utils-debuginfo~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-1_0-0", rpm:"libgstreamer-1_0-0~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-1_0-0-32bit", rpm:"libgstreamer-1_0-0-32bit~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-1_0-0-debuginfo", rpm:"libgstreamer-1_0-0-debuginfo~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libgstreamer-1_0-0-debuginfo-32bit", rpm:"libgstreamer-1_0-0-debuginfo-32bit~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"typelib-1_0-Gst-1_0", rpm:"typelib-1_0-Gst-1_0~1.8.3~10.9.1", rls:"SLES12.0SP5"))) {
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

# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884294");
  script_version("2023-08-04T05:06:23+0000");
  script_cve_id("CVE-2023-1999");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-04 05:06:23 +0000 (Fri, 04 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-07-30 01:02:53 +0000 (Sun, 30 Jul 2023)");
  script_name("CentOS: Security Advisory for libwebp (CESA-2023:2077)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms", re:"ssh/login/release=CentOS7");

  script_xref(name:"Advisory-ID", value:"CESA-2023:2077");
  script_xref(name:"URL", value:"https://lists.centos.org/pipermail/centos-announce/2023-July/086413.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libwebp'
  package(s) announced via the CESA-2023:2077 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The libwebp packages provide a library and tools for the WebP graphics
format. WebP is an image format with a lossy compression of digital
photographic images. WebP consists of a codec based on the VP8 format, and
a container based on the Resource Interchange File Format (RIFF).
Webmasters, web developers and browser developers can use WebP to compress,
archive, and distribute digital images more efficiently.

Security Fix(es):

  * Mozilla: libwebp: Double-free in libwebp (CVE-2023-1999)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section.");

  script_tag(name:"affected", value:"'libwebp' package(s) on CentOS 7.");

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

  if(!isnull(res = isrpmvuln(pkg:"libwebp", rpm:"libwebp~0.3.0~11.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-devel", rpm:"libwebp-devel~0.3.0~11.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-java", rpm:"libwebp-java~0.3.0~11.el7", rls:"CentOS7"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"libwebp-tools", rpm:"libwebp-tools~0.3.0~11.el7", rls:"CentOS7"))) {
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
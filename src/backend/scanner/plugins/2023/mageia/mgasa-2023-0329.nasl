# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0329");
  script_cve_id("CVE-2023-26054", "CVE-2023-28840", "CVE-2023-28841", "CVE-2023-28842");
  script_tag(name:"creation_date", value:"2023-11-30 04:12:11 +0000 (Thu, 30 Nov 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"7.1");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:H/Au:N/C:N/I:C/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:N/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-04-14 15:23:18 +0000 (Fri, 14 Apr 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0329)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0329");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0329.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=31733");
  script_xref(name:"URL", value:"https://github.com/moby/moby/security/advisories/GHSA-vwm3-crmr-xfxw");
  script_xref(name:"URL", value:"https://github.com/moby/buildkit/security/advisories/GHSA-gc89-7gcr-jxqc");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v24.0.5");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v24.0.4");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v24.0.3");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v24.0.2");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v24.0.1");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v24.0.0");
  script_xref(name:"URL", value:"https://github.com/moby/moby/releases/tag/v23.0.3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'docker, docker-containerd' package(s) announced via the MGASA-2023-0329 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update fixes several security issues and also solves some other
issues

- manage change of launch option earlier in post process
- Automatically convert -g option to --data-root in installed
 /etc/sysconfig/docker-storage
- Fix CVE-2023-26054 and CVE-2023-2884[0-2]");

  script_tag(name:"affected", value:"'docker, docker-containerd' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"docker", rpm:"docker~24.0.5~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-containerd", rpm:"docker-containerd~1.7.3~1.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-devel", rpm:"docker-devel~24.0.5~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-fish-completion", rpm:"docker-fish-completion~24.0.5~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-logrotate", rpm:"docker-logrotate~24.0.5~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-nano", rpm:"docker-nano~24.0.5~4.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"docker-zsh-completion", rpm:"docker-zsh-completion~24.0.5~4.mga9", rls:"MAGEIA9"))) {
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

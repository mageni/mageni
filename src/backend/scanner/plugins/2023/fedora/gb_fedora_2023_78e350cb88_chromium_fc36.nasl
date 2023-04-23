# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827478");
  script_version("2023-04-19T10:08:55+0000");
  script_cve_id("CVE-2023-1528", "CVE-2023-1529", "CVE-2023-1530", "CVE-2023-1531", "CVE-2023-1532", "CVE-2023-1533", "CVE-2023-1534", "CVE-2023-1810", "CVE-2023-1811", "CVE-2023-1812", "CVE-2023-1813", "CVE-2023-1814", "CVE-2023-1815", "CVE-2023-1816", "CVE-2023-1817", "CVE-2023-1818", "CVE-2023-1819", "CVE-2023-1820", "CVE-2023-1821", "CVE-2023-1822", "CVE-2023-1823");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-04-19 10:08:55 +0000 (Wed, 19 Apr 2023)");
  script_tag(name:"creation_date", value:"2023-04-13 01:08:11 +0000 (Thu, 13 Apr 2023)");
  script_name("Fedora: Security Advisory for chromium (FEDORA-2023-78e350cb88)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC36");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-78e350cb88");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/HO3QZY4UQFP4XNF43ILMVVOABMB7KAQ5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2023-78e350cb88 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Chromium is an open-source web browser, powered by WebKit (Blink).");

  script_tag(name:"affected", value:"'chromium' package(s) on Fedora 36.");

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

if(release == "FC36") {

  if(!isnull(res = isrpmvuln(pkg:"chromium", rpm:"chromium~112.0.5615.49~1.fc36", rls:"FC36"))) {
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
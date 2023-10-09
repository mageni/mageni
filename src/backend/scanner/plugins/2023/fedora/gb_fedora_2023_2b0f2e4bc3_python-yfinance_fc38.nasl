# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.884694");
  script_version("2023-08-31T05:05:25+0000");
  script_cve_id("CVE-2023-38325");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-08-31 05:05:25 +0000 (Thu, 31 Aug 2023)");
  script_tag(name:"creation_date", value:"2023-08-23 01:10:40 +0000 (Wed, 23 Aug 2023)");
  script_name("Fedora: Security Advisory for python-yfinance (FEDORA-2023-2b0f2e4bc3)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-2b0f2e4bc3");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/NMCCTYY3CSNQBFFYYC5DAV6KATHWCUZK");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-yfinance'
  package(s) announced via the FEDORA-2023-2b0f2e4bc3 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Ever since Yahoo! finance decommissioned their historical data API, many
programs that relied on it to stop working.

yfinance aims to solve this problem by offering a reliable, threaded,
and Pythonic way to download historical market data from Yahoo! finance.");

  script_tag(name:"affected", value:"'python-yfinance' package(s) on Fedora 38.");

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

if(release == "FC38") {

  if(!isnull(res = isrpmvuln(pkg:"python-yfinance", rpm:"python-yfinance~0.2.28~4.fc38", rls:"FC38"))) {
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
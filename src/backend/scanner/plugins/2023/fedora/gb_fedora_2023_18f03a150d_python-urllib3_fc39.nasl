# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885164");
  script_version("2023-12-07T05:05:41+0000");
  script_cve_id("CVE-2023-45803", "CVE-2023-43804");
  script_tag(name:"cvss_base", value:"8.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:N");
  script_tag(name:"last_modification", value:"2023-12-07 05:05:41 +0000 (Thu, 07 Dec 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-10-11 03:15:00 +0000 (Wed, 11 Oct 2023)");
  script_tag(name:"creation_date", value:"2023-11-05 02:19:37 +0000 (Sun, 05 Nov 2023)");
  script_name("Fedora: Security Advisory for python-urllib3 (FEDORA-2023-18f03a150d)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC39");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-18f03a150d");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/5F5CUBAN5XMEBVBZPHFITBLMJV5FIJJ5");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'python-urllib3'
  package(s) announced via the FEDORA-2023-18f03a150d advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"urllib3 is a powerful, user-friendly HTTP client for Python. urllib3 brings
many critical features that are missing from the Python standard libraries:

   Thread safety.
   Connection pooling.
   Client-side SSL/TLS verification.
   File uploads with multipart encoding.
   Helpers for retrying requests and dealing with HTTP redirects.
   Support for gzip, deflate, brotli, and zstd encoding.
   Proxy support for HTTP and SOCKS.
   100% test coverage.");

  script_tag(name:"affected", value:"'python-urllib3' package(s) on Fedora 39.");

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

if(release == "FC39") {

  if(!isnull(res = isrpmvuln(pkg:"python-urllib3", rpm:"python-urllib3~1.26.18~1.fc39", rls:"FC39"))) {
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
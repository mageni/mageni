# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885034");
  script_version("2023-10-27T16:11:33+0000");
  script_cve_id("CVE-2023-26117", "CVE-2023-26116", "CVE-2023-26118");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"last_modification", value:"2023-10-27 16:11:33 +0000 (Fri, 27 Oct 2023)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-05-30 17:20:00 +0000 (Tue, 30 May 2023)");
  script_tag(name:"creation_date", value:"2023-10-20 01:19:37 +0000 (Fri, 20 Oct 2023)");
  script_name("Fedora: Security Advisory for icecat (FEDORA-2023-7342330743)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-7342330743");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/OQWJLE5WE33WNMA54XSJIDXBRK2KL3XJ");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'icecat'
  package(s) announced via the FEDORA-2023-7342330743 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"GNU IceCat is the GNU version of the Firefox ESR browser.
Extensions included to this version of IceCat:

  * LibreJS
   GNU LibreJS aims to address the JavaScript problem described in the article
   'The JavaScript Trap' of Richard Stallman.

  * HTTPS Everywhere
   HTTPS Everywhere is an extension that encrypts your communications with
   many major websites, making your browsing more secure.

  * A set of companion extensions for LibreJS by Nathan Nichols
   are pre-installed.

  * A series of configuration changes and tweaks were applied to ensure that
   IceCat does not initiate network connections that the user has not explicitly
   requested. This implies not downloading feeds, updates, blacklists or any
   other similar data needed during startup.");

  script_tag(name:"affected", value:"'icecat' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"icecat", rpm:"icecat~115.3.1~7.rh2.fc38", rls:"FC38"))) {
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

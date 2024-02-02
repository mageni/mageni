# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.885573");
  script_version("2024-02-02T05:06:11+0000");
  script_cve_id("CVE-2023-51766");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:11 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2024-02-02 02:22:45 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"creation_date", value:"2024-01-18 09:16:35 +0000 (Thu, 18 Jan 2024)");
  script_name("Fedora: Security Advisory for exim (FEDORA-2024-e0841c83bb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2024-e0841c83bb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/ORN7OKEQPPBKUHYRQ6LR5PSNBQVDHAWB");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'exim'
  package(s) announced via the FEDORA-2024-e0841c83bb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Exim is a message transfer agent (MTA) developed at the University of
Cambridge for use on Unix systems connected to the Internet. It is
freely available under the terms of the GNU General Public Licence. In
style it is similar to Smail 3, but its facilities are more
general. There is a great deal of flexibility in the way mail can be
routed, and there are extensive facilities for checking incoming
mail. Exim can be installed in place of sendmail, although the
configuration of exim is quite different to that of sendmail.");

  script_tag(name:"affected", value:"'exim' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"exim", rpm:"exim~4.97.1~1.fc38", rls:"FC38"))) {
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
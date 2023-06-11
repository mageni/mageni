# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.827791");
  script_version("2023-06-02T09:09:16+0000");
  script_cve_id("CVE-2023-22970");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"last_modification", value:"2023-06-02 09:09:16 +0000 (Fri, 02 Jun 2023)");
  script_tag(name:"creation_date", value:"2023-05-30 01:06:35 +0000 (Tue, 30 May 2023)");
  script_name("Fedora: Security Advisory for bottles (FEDORA-2023-cc571303eb)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Fedora Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/fedora", "ssh/login/rpms", re:"ssh/login/release=FC38");

  script_xref(name:"Advisory-ID", value:"FEDORA-2023-cc571303eb");
  script_xref(name:"URL", value:"https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/2JZXK7OK6ZO5IWT5V3YADXDGVVJ6TYBU");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'bottles'
  package(s) announced via the FEDORA-2023-cc571303eb advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"Easily manage Wine prefix in a new way! (Run Windows software and games on
Linux).

Features:

  * Create bottles based on environments (a set of rule and dependencies for
    better software compatibility)

  * Access to a customizable environment for all your experiments

  * Run every executable (.exe/.msi) in your bottles, using the context menu
    in your file manager

  * Integrated management and storage for executable file arguments

  * Support for custom environment variables

  * Simplified DLL overrides

  * On-the-fly runner change for any Bottle

  * Various optimizations for better gaming performance (esync, fsync, dxvk,
    cache, shader compiler, offload .. and much more.)

  * Tweak different wine prefix settings, without leaving Bottles

  * Automated dxvk installation

  * Automatic installation and management of Wine and Proton runners

  * System for checking runner updates for the bottle and automatic repair in
    case of breakage

  * Integrated Dependencies installer with compatibility check based on a
    community-driver repository

  * Detection of installed programs

  * Integrated Task manager for wine processes

  * Easy access to ProtonDB and WineHQ for support

  * Configurations update system across Bottles versions

  * Backup bottles as configuration file or full archive

  * Import backup archive

  * Importer from Bottles v1 (and other wineprefix manager)

  * Bottles versioning (experimental)

  * .. and much more that you can find by installing Bottles!");

  script_tag(name:"affected", value:"'bottles' package(s) on Fedora 38.");

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

  if(!isnull(res = isrpmvuln(pkg:"bottles", rpm:"bottles~51.6~1.fc38", rls:"FC38"))) {
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
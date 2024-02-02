# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.10.2023.0341");
  script_cve_id("CVE-2023-48231", "CVE-2023-48232", "CVE-2023-48233", "CVE-2023-48234", "CVE-2023-48235", "CVE-2023-48236", "CVE-2023-48237", "CVE-2023-48706");
  script_tag(name:"creation_date", value:"2023-12-11 04:12:28 +0000 (Mon, 11 Dec 2023)");
  script_version("2024-02-02T05:06:10+0000");
  script_tag(name:"last_modification", value:"2024-02-02 05:06:10 +0000 (Fri, 02 Feb 2024)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:H/Au:N/C:N/I:N/A:C");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2023-12-01 17:54:29 +0000 (Fri, 01 Dec 2023)");

  script_name("Mageia: Security Advisory (MGASA-2023-0341)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("Mageia Linux Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/mageia_linux", "ssh/login/release", re:"ssh/login/release=MAGEIA9");

  script_xref(name:"Advisory-ID", value:"MGASA-2023-0341");
  script_xref(name:"URL", value:"https://advisories.mageia.org/MGASA-2023-0341.html");
  script_xref(name:"URL", value:"https://bugs.mageia.org/show_bug.cgi?id=32546");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/11/16/1");
  script_xref(name:"URL", value:"https://www.openwall.com/lists/oss-security/2023/11/22/3");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'vim' package(s) announced via the MGASA-2023-0341 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"The updated packages fix security vulnerabilities

When closing a window, vim may try to access already freed window
structure. Exploitation beyond crashing the application has not been
shown to be viable. (CVE-2023-48231)

A floating point exception may occur when calculating the line offset
for overlong lines and smooth scrolling is enabled and the cpo-settings
include the 'n' flag. This may happen when a window border is present
and when the wrapped line continues on the next physical line directly
in the window border because the 'cpo' setting includes the 'n' flag.
Only users with non-default settings are affected and the exception
should only result in a crash. (CVE-2023-48232)

If the count after the :s command is larger than what fits into a
(signed) long variable, abort with e_value_too_large. Impact is low,
user interaction is required and a crash may not even happen in all
situations. (CVE-2023-48233)

When getting the count for a normal mode z command, it may overflow for
large counts given. Impact is low, user interaction is required and a
crash may not even happen in all situations. (CVE-2023-48234)

When parsing relative ex addresses one may unintentionally cause an
overflow. Ironically this happens in the existing overflow check,
because the line number becomes negative and LONG_MAX - lnum will cause
the overflow. Impact is low, user interaction is required and a crash
may not even happen in all situations. (CVE-2023-48235)

When using the z= command, the user may overflow the count with values
larger than MAX_INT. Impact is low, user interaction is required and a
crash may not even happen in all situations. (CVE-2023-48236)

In affected versions when shifting lines in operator pending mode and
using a very large value, it may be possible to overflow the size of
integer. Impact is low, user interaction is required and a crash may not
even happen in all situations. (CVE-2023-48237)

When executing a `:s` command for the very first time and using a
sub-replace-special atom inside the substitution part, it is possible
that the recursive `:s` call causes free-ing of memory which may later
then be accessed by the initial `:s` command. The user must
intentionally execute the payload and the whole process is a bit tricky
to do since it seems to work only reliably for the very first :s
command. It may also cause a crash of Vim. (CVE-2023-48706)

The update fixes haproxy configuration paths used for syntax coloration.");

  script_tag(name:"affected", value:"'vim' package(s) on Mageia 9.");

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

  if(!isnull(res = isrpmvuln(pkg:"vim", rpm:"vim~9.0.2130~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-X11", rpm:"vim-X11~9.0.2130~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-common", rpm:"vim-common~9.0.2130~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-enhanced", rpm:"vim-enhanced~9.0.2130~2.mga9", rls:"MAGEIA9"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"vim-minimal", rpm:"vim-minimal~9.0.2130~2.mga9", rls:"MAGEIA9"))) {
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

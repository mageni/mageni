###############################################################################
# OpenVAS Vulnerability Test
#
# RedHat Update for grep RHSA-2015:2111-07
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.871494");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2015-11-20 06:23:10 +0100 (Fri, 20 Nov 2015)");
  script_cve_id("CVE-2015-1345");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("RedHat Update for grep RHSA-2015:2111-07");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'grep'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"The grep utility searches through textual
input for lines that contain a match to a specified pattern and then prints the
matching lines. The GNU grep utilities include grep, egrep, and fgrep.

A heap-based buffer overflow flaw was found in the way grep processed
certain pattern and text combinations. An attacker able to trick a user
into running grep on specially crafted input could use this flaw to crash
grep or, potentially, read from uninitialized memory. (CVE-2015-1345)

This update also fixes the following bugs:

  * Prior to this update, the \w and \W symbols were inconsistently matched
to the [:alnum:] character class. Consequently, using regular expressions
with '\w' and '\W' could lead to incorrect results. With this update, '\w'
is consistently matched to the [_[:alnum:]] character, and '\W' is
consistently matched to the [^_[:alnum:]] character. (BZ#1159012)

  * Previously, the Perl Compatible Regular Expression (PCRE) matcher
(selected by the '-P' parameter in grep) did not work correctly when
matching non-UTF-8 text in UTF-8 locales. Consequently, an error message
about invalid UTF-8 byte sequence characters was returned. To fix this bug,
patches from upstream have been applied to the grep utility. As a result,
PCRE now skips non-UTF-8 characters as non-matching text without returning
any error message. (BZ#1217080)

All grep users are advised to upgrade to these updated packages, which
contain backported patches to correct these issues.");
  script_tag(name:"affected", value:"grep on Red Hat Enterprise Linux Server (v. 7)");
  script_tag(name:"solution", value:"Please Install the Updated Packages.");
  script_xref(name:"URL", value:"https://www.redhat.com/archives/rhsa-announce/2015-November/msg00021.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Red Hat Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/rhel", "ssh/login/rpms", re:"ssh/login/release=RHENT_7");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "RHENT_7")
{

  if ((res = isrpmvuln(pkg:"grep", rpm:"grep~2.20~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"grep-debuginfo", rpm:"grep-debuginfo~2.20~2.el7", rls:"RHENT_7")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

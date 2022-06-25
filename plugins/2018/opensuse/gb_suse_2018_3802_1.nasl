###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_3802_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for libxkbcommon openSUSE-SU-2018:3802-1 (libxkbcommon)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
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
  script_oid("1.3.6.1.4.1.25623.1.0.852125");
  script_version("$Revision: 12497 $");
  script_cve_id("CVE-2018-15853", "CVE-2018-15854", "CVE-2018-15855", "CVE-2018-15856",
                "CVE-2018-15857", "CVE-2018-15858", "CVE-2018-15859", "CVE-2018-15861",
                "CVE-2018-15862", "CVE-2018-15863", "CVE-2018-15864");
  script_tag(name:"cvss_base", value:"4.6");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-11-17 06:14:44 +0100 (Sat, 17 Nov 2018)");
  script_name("SuSE Update for libxkbcommon openSUSE-SU-2018:3802-1 (libxkbcommon)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap15\.0");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-11/msg00024.html");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'libxkbcommon'
  package(s) announced via the openSUSE-SU-2018:3802_1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for libxkbcommon to version 0.8.2 fixes the following issues:

  - Fix a few NULL-dereferences, out-of-bounds access and undefined behavior
  in the XKB text format parser.

  - CVE-2018-15853: Endless recursion could have been used by local
  attackers to crash xkbcommon users by supplying a crafted keymap file
  that triggers boolean negation (bsc#1105832).

  - CVE-2018-15854: Unchecked NULL pointer usage could have been used by
  local attackers to crash (NULL pointer dereference) the xkbcommon parser
  by supplying a crafted keymap file, because geometry tokens were
  desupported incorrectly (bsc#1105832).

  - CVE-2018-15855: Unchecked NULL pointer usage could have been used by
  local attackers to crash (NULL pointer dereference) the xkbcommon parser
  by supplying a crafted keymap file, because the XkbFile for an
  xkb_geometry section was mishandled (bsc#1105832).

  - CVE-2018-15856: An infinite loop when reaching EOL unexpectedly could be
  used by local attackers to cause a denial of service during parsing of
  crafted keymap files (bsc#1105832).

  - CVE-2018-15857: An invalid free in ExprAppendMultiKeysymList could have
  been used by local attackers to crash xkbcommon keymap parsers or
  possibly have unspecified other impact by supplying a crafted keymap
  file (bsc#1105832).

  - CVE-2018-15858: Unchecked NULL pointer usage when handling invalid
  aliases in CopyKeyAliasesToKeymap could have been used by local
  attackers to crash (NULL pointer dereference) the xkbcommon parser by
  supplying a crafted keymap file (bsc#1105832).

  - CVE-2018-15859: Unchecked NULL pointer usage when parsing invalid atoms
  in ExprResolveLhs could have been used by local attackers to crash (NULL
  pointer dereference) the xkbcommon parser by supplying a crafted keymap
  file, because lookup failures are mishandled (bsc#1105832).

  - CVE-2018-15861: Unchecked NULL pointer usage in ExprResolveLhs could
  have been used by local attackers to crash (NULL pointer dereference)
  the xkbcommon parser by supplying a crafted keymap file that triggers an
  xkb_intern_atom failure (bsc#1105832).

  - CVE-2018-15862: Unchecked NULL pointer usage in LookupModMask could have
  been used by local attackers to crash (NULL pointer dereference) the
  xkbcommon parser by supplying a crafted keymap file with invalid virtual
  modifiers (bsc#1105832).

  - CVE-2018-15863: Unchecked NULL pointer usage in ResolveStateAndPredicate
  could have been used by local attackers to crash (NULL pointer
  dereference) the xkbcommon parser by supplying a crafted keymap file
  with a no-op modmask expression (b ...

  Description truncated, please see the referenced URL(s) for more information.");

  script_tag(name:"affected", value:"libxkbcommon on openSUSE Leap 15.0.");

  script_tag(name:"solution", value:"Please install the updated package(s).");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);

res = "";

if(release == "openSUSELeap15.0")
{

  if ((res = isrpmvuln(pkg:"libxkbcommon-debugsource", rpm:"libxkbcommon-debugsource~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-devel", rpm:"libxkbcommon-devel~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11-0", rpm:"libxkbcommon-x11-0~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11-0-debuginfo", rpm:"libxkbcommon-x11-0-debuginfo~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11-devel", rpm:"libxkbcommon-x11-devel~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon0", rpm:"libxkbcommon0~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon0-debuginfo", rpm:"libxkbcommon0-debuginfo~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-devel-32bit", rpm:"libxkbcommon-devel-32bit~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11-0-32bit", rpm:"libxkbcommon-x11-0-32bit~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11-0-32bit-debuginfo", rpm:"libxkbcommon-x11-0-32bit-debuginfo~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon-x11-devel-32bit", rpm:"libxkbcommon-x11-devel-32bit~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon0-32bit", rpm:"libxkbcommon0-32bit~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"libxkbcommon0-32bit-debuginfo", rpm:"libxkbcommon0-32bit-debuginfo~0.8.2~lp150.2.3.1", rls:"openSUSELeap15.0")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

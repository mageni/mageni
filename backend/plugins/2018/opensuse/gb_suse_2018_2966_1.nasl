###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_suse_2018_2966_1.nasl 12497 2018-11-23 08:28:21Z cfischer $
#
# SuSE Update for zsh openSUSE-SU-2018:2966-1 (zsh)
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (C) 2018 Greenbone Networks GmbH, http://www.greenbone.net
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
  script_oid("1.3.6.1.4.1.25623.1.0.851921");
  script_version("$Revision: 12497 $");
  script_tag(name:"last_modification", value:"$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $");
  script_tag(name:"creation_date", value:"2018-10-03 08:06:44 +0200 (Wed, 03 Oct 2018)");
  script_cve_id("CVE-2018-0502", "CVE-2018-1071", "CVE-2018-1083", "CVE-2018-1100", "CVE-2018-13259");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"qod_type", value:"package");
  script_name("SuSE Update for zsh openSUSE-SU-2018:2966-1 (zsh)");
  script_tag(name:"summary", value:"The remote host is missing an update for the 'zsh'
  package(s) announced via the referenced advisory.");
  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");
  script_tag(name:"insight", value:"This update for zsh to version 5.6.2 fixes the following issues:

  These security issues were fixed:

  - CVE-2018-0502: The beginning of a #! script file was mishandled,
  potentially leading to an execve call to a program named on the second
  line (bsc#1107296)

  - CVE-2018-13259: Shebang lines exceeding 64 characters were truncated,
  potentially leading to an execve call to a program name that is a
  substring of the intended one (bsc#1107294)

  - CVE-2018-1100: Prevent stack-based buffer overflow in the
  utils.c:checkmailpath function that allowed local attackers to execute
  arbitrary code in the context of another user (bsc#1089030).

  - CVE-2018-1071: Prevent stack-based buffer overflow in the
  exec.c:hashcmd() function that allowed local attackers to cause a denial
  of service (bsc#1084656).

  - CVE-2018-1083: Prevent buffer overflow in the shell autocomplete
  functionality that allowed local unprivileged users to create a
  specially crafted directory path which lead to code execution in the
  context of the user who tries to use autocomplete to traverse the
  mentioned path (bsc#1087026).

  - Disallow evaluation of the initial values of integer variables imported
  from the environment

  These non-security issues were fixed:

  - Fixed that the signal SIGWINCH was being ignored when zsh is not in the
  foreground.

  - Fixed two regressions with pipelines getting backgrounded and emitting
  the signal SIGTTOU

  - The effect of the NO_INTERACTIVE_COMMENTS option extends into $(...) and
  `...` command substitutions when used on the command line.

  - The 'exec' and 'command' precommand modifiers, and options to them, are
  now parsed after parameter expansion.

  - Functions executed by ZLE widgets no longer have their standard input
  closed, but redirected from /dev/null instead.

  - There is an option WARN_NESTED_VAR, a companion to the existing
  WARN_CREATE_GLOBAL that causes a warning if a function updates a
  variable from an enclosing scope without using typeset -g.

  - zmodload now has an option -s to be silent on a failure to find a module
  but still print other errors.

  - Fix typo in chflags completion

  - Fixed invalid git commands completion

  - VCS info system: vcs_info git: Avoid a fork.

  - Fix handling of 'printf -' and 'printf --'

  - fix broken completion for filterdiff (boo#1019130)

  - Unicode9 support, this needs support from your terminal to work
  correctly.

  - The new word modifier ':P' computes the physical path of the argument.

  - The output of 'typeset -p' uses 'export' commands or the '-g'
  option for parameters that are not local to the cu ...

  Description truncated, please see the referenced URL(s) for more information.");
  script_tag(name:"affected", value:"zsh on openSUSE Leap 42.3");
  script_tag(name:"solution", value:"Please install the updated packages.");

  script_xref(name:"URL", value:"http://lists.opensuse.org/opensuse-security-announce/2018-10/msg00001.html");
  script_tag(name:"solution_type", value:"VendorFix");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2018 Greenbone Networks GmbH");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse", "ssh/login/rpms", re:"ssh/login/release=openSUSELeap42\.3");
  exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-rpm.inc");

release = rpm_get_ssh_release();
if(!release) exit(0);
res = "";

if(release == "openSUSELeap42.3")
{

  if ((res = isrpmvuln(pkg:"zsh", rpm:"zsh~5.6.2~9.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zsh-debuginfo", rpm:"zsh-debuginfo~5.6.2~9.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zsh-debugsource", rpm:"zsh-debugsource~5.6.2~9.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"zsh-htmldoc", rpm:"zsh-htmldoc~5.6.2~9.6.1", rls:"openSUSELeap42.3")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99);
  exit(0);
}

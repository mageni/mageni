# SPDX-FileCopyrightText: 2023 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2023.2485.1");
  script_cve_id("CVE-2017-16829", "CVE-2018-7208");
  script_tag(name:"creation_date", value:"2023-06-12 14:16:29 +0000 (Mon, 12 Jun 2023)");
  script_version("2023-06-20T05:05:26+0000");
  script_tag(name:"last_modification", value:"2023-06-20 05:05:26 +0000 (Tue, 20 Jun 2023)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2019-10-31 01:15:00 +0000 (Thu, 31 Oct 2019)");

  script_name("SUSE: Security Advisory (SUSE-SU-2023:2485-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2023 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2023:2485-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2023/suse-su-20232485-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the SUSE-SU-2023:2485-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdb fixes the following issues:
gdb was updated to 12.1. (jsc#SLE-21561)


DBX mode is deprecated, and will be removed in GDB 13.


GDB 12 is the last release of GDB that will support building against
 Python 2. From GDB 13, it will only be possible to build GDB itself
 with Python 3 support.


Improved C++ template support:


GDB now treats functions/types involving C++ templates like it does function
 overloads. Users may omit parameter lists to set breakpoints on families of
 template functions, including types/functions composed of multiple template types:
 (gdb) break template_func(template_1, int)
 The above will set breakpoints at every function template_func&#x27, where
 the first function parameter is any template type namedtemplate_1' and
 the second function parameter is `int'.
 TAB completion also gains similar improvements.


New commands:


maint set backtrace-on-fatal-signal on<pipe>off

maint show backtrace-on-fatal-signal

This setting is 'on' by default. When 'on' GDB will print a limited
 backtrace to stderr in the situation where GDB terminates with a
 fatal signal. This only supported on some platforms where the
 backtrace and backtrace_symbols_fd functions are available.

set source open on<pipe>off show source open

This setting, which is on by default, controls whether GDB will try
 to open source code files. Switching this off will stop GDB trying
 to open and read source code files, which can be useful if the files
 are located over a slow network connection.

set varsize-limit show varsize-limit

These are now deprecated aliases for 'set max-value-size' and
 'show max-value-size'.

task apply [all <pipe> TASK-IDS...] [FLAG]... COMMAND

Like 'thread apply', but applies COMMAND to Ada tasks.

watch [...] task ID

Watchpoints can now be restricted to a specific Ada task.

maint set internal-error backtrace on<pipe>off maint show internal-error backtrace maint set internal-warning backtrace on<pipe>off maint show internal-warning backtrace

GDB can now print a backtrace of itself when it encounters either an
 internal-error, or an internal-warning. This is on by default for
 internal-error and off by default for internal-warning.

set logging on<pipe>off

Deprecated and replaced by 'set logging enabled on<pipe>off'.

set logging enabled on<pipe>off show logging enabled

These commands set or show whether logging is enabled or disabled.

exit

You can now exit GDB by using the new command 'exit', in addition to
 the existing 'quit' command.

set debug threads on<pipe>off show debug threads

Print additional debug messages about thread creation and deletion.

set debug linux-nat on<pipe>off show debug linux-nat

These new commands replaced the old 'set debug lin-lwp' and 'show
 debug lin-lwp' respectively. Turning this setting on prints debug
 messages relating to GDB's handling of native Linux inferiors.

maint flush ... [Please see the references for more information on the vulnerabilities]");

  script_tag(name:"affected", value:"'gdb' package(s) on SUSE Linux Enterprise High Performance Computing 12-SP5, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP Applications 12-SP5, SUSE Linux Enterprise Software Development Kit 12-SP5.");

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

if(release == "SLES12.0SP5") {

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~12.1~2.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debuginfo", rpm:"gdb-debuginfo~12.1~2.20.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debugsource", rpm:"gdb-debugsource~12.1~2.20.1", rls:"SLES12.0SP5"))) {
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

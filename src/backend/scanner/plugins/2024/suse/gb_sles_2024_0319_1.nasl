# SPDX-FileCopyrightText: 2024 Greenbone AG
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-only

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.1.4.2024.0319.1");
  script_cve_id("CVE-2017-16829", "CVE-2018-7208", "CVE-2022-4806");
  script_tag(name:"creation_date", value:"2024-02-02 15:00:06 +0000 (Fri, 02 Feb 2024)");
  script_version("2024-02-05T05:05:38+0000");
  script_tag(name:"last_modification", value:"2024-02-05 05:05:38 +0000 (Mon, 05 Feb 2024)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_tag(name:"severity_vector", value:"CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2018-03-19 15:09:05 +0000 (Mon, 19 Mar 2018)");

  script_name("SUSE: Security Advisory (SUSE-SU-2024:0319-1)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2024 Greenbone AG");
  script_family("SuSE Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/suse_sles", "ssh/login/rpms", re:"ssh/login/release=(SLES12\.0SP5)");

  script_xref(name:"Advisory-ID", value:"SUSE-SU-2024:0319-1");
  script_xref(name:"URL", value:"https://www.suse.com/support/update/announcement/2024/suse-su-20240319-1/");

  script_tag(name:"summary", value:"The remote host is missing an update for the 'gdb' package(s) announced via the SUSE-SU-2024:0319-1 advisory.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable package version is present on the target host.");

  script_tag(name:"insight", value:"This update for gdb fixes the following issues:

Drop libdebuginfod1 BuildRequires/Recommends. The former isn't
 needed because there's a build requirement on libdebuginfod-devel
 already, which will pull the shared library. And the latter,
 because it's bogus since RPM auto generated dependency will take
 care of that requirement.

gdb was released in 13.2:


This version of GDB includes the following changes and enhancements:


Support for the following new targets has been added in both GDB and GDBserver:
* GNU/Linux/LoongArch (gdbserver) loongarch*-*-linux*
* GNU/Linux/CSKY (gdbserver) csky*-*linux*



The Windows native target now supports target async.

Floating-point support has now been added on LoongArch GNU/Linux.

New commands:
* set print nibbles [on<pipe>off]
* show print nibbles

* This controls whether the &#x27,print/t&#x27, command will display binary values in groups of four bits, known as &quot,nibbles&quot,. The default is &#x27,off&#x27,.
 Various styling-related commands. See the gdb/NEWS file for more details.
 Various maintenance commands. These are normally aimed at GDB experts or developers. See the gdb/NEWS file for more details.



Python API improvements:
 * New Python API for instruction disassembly.

 * The new attribute &#x27,locations&#x27, of gdb.Breakpoint returns a list of gdb.BreakpointLocation objects specifying the locations where the breakpoint is inserted into the debuggee.
 * New Python type gdb.BreakpointLocation.
 * New function gdb.format_address(ADDRESS, PROGSPACE, ARCHITECTURE) that formats ADDRESS as &#x27,address &#x27,
 * New function gdb.current_language that returns the name of the current language. Unlike gdb.parameter(&#x27,language&#x27,), this will never return &#x27,auto&#x27,.
 * New function gdb.print_options that returns a dictionary of the prevailing print options, in the form accepted by gdb.Value.format_string.
 * New method gdb.Frame.language that returns the name of the frame&#x27,s language.
 * gdb.Value.format_string now uses the format provided by &#x27,print&#x27,, if it is called during a &#x27,print&#x27, or other similar operation.
 * gdb.Value.format_string now accepts the &#x27,summary&#x27, keyword. This can be used to request a shorter representation of a value, the way that &#x27,set print frame-arguments scalars&#x27, does.
 * The gdb.register_window_type method now restricts the set of acceptable window names. The first character of a window&#x27,s name must start with a character in the set [a-zA-Z], every subsequent character of a window&#x27,s name must be in the set [-_.a-zA-Z0-9].



GDB/MI changes:

MI version 1 is deprecated, and will be removed in GDB 14.
The async record stating the stopped reason 'breakpoint-hit' now contains an optional field locno.





Miscellaneous improvements:
 * gdb now supports zstd compressed debug sections (ELFCOMPRESS_ZSTD) for ELF.
 * New convenience ... [Please see the references for more information on the vulnerabilities]");

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

  if(!isnull(res = isrpmvuln(pkg:"gdb", rpm:"gdb~13.2~2.23.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debuginfo", rpm:"gdb-debuginfo~13.2~2.23.1", rls:"SLES12.0SP5"))) {
    report += res;
  }

  if(!isnull(res = isrpmvuln(pkg:"gdb-debugsource", rpm:"gdb-debugsource~13.2~2.23.1", rls:"SLES12.0SP5"))) {
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

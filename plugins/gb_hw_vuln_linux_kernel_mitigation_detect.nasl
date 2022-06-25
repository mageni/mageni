# Copyright (C) 2020 Greenbone Networks GmbH
# Some text descriptions might be excerpted from (a) referenced
# source(s), and are Copyright (C) by the respective right holder(s).
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108765");
  script_version("2020-06-02T12:13:38+0000");
  script_tag(name:"last_modification", value:"2020-06-09 11:12:11 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Detection of Linux Kernel mitigation status for hardware vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/uname");
  script_exclude_keys("ssh/no_linux_shell");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html");

  script_tag(name:"summary", value:"Checks the Linux Kernel mitigation status for hardware (CPU) vulnerabilities.");

  script_tag(name:"qod", value:"80"); # nb: None of the existing QoD types are matching here

  exit(0);
}

include("ssh_func.inc");
include("misc_func.inc");

uname = get_kb_item( "ssh/login/uname" );
if( ! uname || ! eregmatch( string:uname, pattern:"^Linux ", icase:FALSE ) ) # nb: Currently only Linux Kernel supported
  exit( 0 );

sock = ssh_login_or_reuse_connection();
if( ! sock )
  exit( 0 );

path = "/sys/devices/system/cpu/vulnerabilities/";
res = ssh_cmd( socket:sock, cmd:"ls -d " + path + "*", return_errors:TRUE, return_linux_errors_only:TRUE );
res = chomp( res );
if( ! res || ! strlen( res ) ) {
  ssh_close_connection();
  exit( 0 );
}

if( res =~ "command not found" ) { # nb: ls should be always available but still checking to avoid false positives
  ssh_close_connection();
  log_message( port:0, data:"Possible Linux system found but mandatory 'ls' command missing. Can't continue. Response: " + res );
  exit( 0 );
}

if( failed = egrep( string:res, pattern:": (Permission denied|cannot open )", icase:TRUE ) ) {

  ssh_close_connection();

  set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/access_failed", value:TRUE );

  report = 'Access to the "' + path + '" sysfs interface not possible:\n\n' + chomp( failed );
  log_message( port:0, data:report );
  exit( 0 );
}

not_found = egrep( string:res, pattern:": No such file or directory", icase:TRUE );
if( not_found || ! egrep( string:res, pattern:"^" + path, icase:FALSE ) ) {

  ssh_close_connection();

  if( not_found )
    report = not_found;
  else
    report = res;

  report  = '"' + path + '" sysfs interface not available:\n\n' + chomp( report );
  report += '\n\nBased on this it is assumed that no Linux Kernel mitigations are available.';

  set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/sysfs_not_available", value:TRUE );
  set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/sysfs_not_available/report", value:report );
  log_message( port:0, data:report );
  exit( 0 );
}

# nb: Keep in sync with the mitigation <-> CVE list maintained in 2020/gb_hw_vuln_linux_kernel_mitigation_missing.nasl
known_mitigations = make_list(
  "itlb_multihit",
  "l1tf",
  "mds",
  "meltdown",
  "spec_store_bypass",
  "spectre_v1",
  "spectre_v2",
  "tsx_async_abort" );

info = make_array();

foreach known_mitigation( known_mitigations ) {

  # Examples gathered with:
  #
  # grep ^ /dev/null /sys/devices/system/cpu/vulnerabilities/*
  #
  # from Kernel 5.6.0-1 on Debian bullseye/sid:
  # /sys/devices/system/cpu/vulnerabilities/itlb_multihit:KVM: Mitigation: Split huge pages
  # /sys/devices/system/cpu/vulnerabilities/l1tf:Mitigation: PTE Inversion; VMX: conditional cache flushes, SMT vulnerable
  # /sys/devices/system/cpu/vulnerabilities/mds:Mitigation: Clear CPU buffers; SMT vulnerable
  # /sys/devices/system/cpu/vulnerabilities/meltdown:Mitigation: PTI
  # /sys/devices/system/cpu/vulnerabilities/spec_store_bypass:Mitigation: Speculative Store Bypass disabled via prctl and seccomp
  # /sys/devices/system/cpu/vulnerabilities/spectre_v1:Mitigation: usercopy/swapgs barriers and __user pointer sanitization
  # /sys/devices/system/cpu/vulnerabilities/spectre_v2:Mitigation: Full generic retpoline, IBPB: conditional, IBRS_FW, STIBP: conditional, RSB filling
  # /sys/devices/system/cpu/vulnerabilities/tsx_async_abort:Not affected
  #
  # from Kernel 4.9.0-8 on Debian stretch:
  # /sys/devices/system/cpu/vulnerabilities/l1tf:Mitigation: PTE Inversion
  # /sys/devices/system/cpu/vulnerabilities/meltdown:Mitigation: PTI
  # /sys/devices/system/cpu/vulnerabilities/spec_store_bypass:Vulnerable
  # /sys/devices/system/cpu/vulnerabilities/spectre_v1:Mitigation: __user pointer sanitization
  # /sys/devices/system/cpu/vulnerabilities/spectre_v2:Mitigation: Full generic retpoline
  #
  # from Kernel 3.10.0-327.62.59.83.h195 on EulerOS 2.0 SP2:
  # /sys/devices/system/cpu/vulnerabilities/l1tf:Mitigation: PTE Inversion
  # /sys/devices/system/cpu/vulnerabilities/mds:Mitigation: Clear CPU buffers; SMT Host state unknown
  # /sys/devices/system/cpu/vulnerabilities/meltdown:Mitigation: PTI
  # /sys/devices/system/cpu/vulnerabilities/spec_store_bypass:Vulnerable
  # /sys/devices/system/cpu/vulnerabilities/spectre_v1:Mitigation: Load fences, usercopy/swapgs barriers and __user pointer sanitization
  # /sys/devices/system/cpu/vulnerabilities/spectre_v2:Vulnerable: Retpoline without IBPB
  #
  file = path + known_mitigation;
  cmd = "cat " + file;
  res = ssh_cmd( socket:sock, cmd:cmd, return_errors:TRUE, return_linux_errors_only:FALSE );
  res = chomp( res );
  if( res =~ ": No such file or directory" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/list", value:file + "###----###---###sysfs file missing" );
  } else if( res =~ "vulnerable" ) { # nb: case insensitive match because there is "Vulnerable" vs. "SMT vulnerable"
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/list", value:file + "###----###---###" + res );
  } else if( res =~ "Mitigation: " ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/available", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/available/list", value:file + "###----###---###" + res );
  } else if( res =~ "Not affected" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/not_affected", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/not_affected/list", value:file + "###----###---###" + res );
  # nb: On EulerOS with a non-privileged user we're allowed to do a directly listing (the initial check) but not reading the files itself.
  } else if( res =~ ": Permission denied" ) {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/permission_denied", value:TRUE );
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/permission_denied/list", value:file + "###----###---###" + res );
  } else {
    set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown", value:TRUE );
    if( ! res ) {
      res = 'Unknown: No answer received to command "' + cmd + '"';
      set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown/list", value:file + "###----###---###No answer received" );
    } else {
      res = 'Unknown: Unrecognized answer received to command "' + cmd + '": ' + res;
      set_kb_item( name:"ssh/hw_vulns/kernel_mitigations/unknown/list", value:file + "###----###---###" + res );
    }
  }

  info[file] = res;
}

report  = 'Linux Kernel mitigation status for hardware vulnerabilities:\n\n';
report += text_format_table( array:info, sep:" | ", columnheader:make_list( "sysfs file", "Kernel status" ) );
report += '\n\nNotes on Kernel status output column:';
report += '\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the kernel doesn\'t know this vulnerability yet and is not providing any mitigation which means the target system is vulnerable.';
report += '\n- Strings including "Mitigation:", "Not affected" or "Vulnerable" are directly reportedby the Linux Kernel.';
report += '\n- All other strings are responses to various SSH commands.';

log_message( port:0, data:report );

exit( 0 );

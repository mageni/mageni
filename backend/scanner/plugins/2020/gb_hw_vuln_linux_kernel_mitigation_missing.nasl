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
  script_oid("1.3.6.1.4.1.25623.1.0.108766");
  script_version("2020-06-02T12:13:38+0000");
  script_cve_id("CVE-2017-5753", "CVE-2017-5715", "CVE-2017-5754", "CVE-2019-1125", "CVE-2018-3639",
                "CVE-2018-3615", "CVE-2018-3620", "CVE-2018-3646", "CVE-2018-12126", "CVE-2018-12130",
                "CVE-2018-12127", "CVE-2019-11091", "CVE-2019-11135", "CVE-2018-12207");
  script_tag(name:"last_modification", value:"2020-06-09 11:12:11 +0000 (Tue, 09 Jun 2020)");
  script_tag(name:"creation_date", value:"2020-06-02 05:50:19 +0000 (Tue, 02 Jun 2020)");
  script_tag(name:"cvss_base", value:"4.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_name("Missing Linux Kernel mitigations for hardware vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2020 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hw_vuln_linux_kernel_mitigation_detect.nasl");
  script_mandatory_keys("ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/index.html");

  script_tag(name:"summary", value:"The remote host is missing one or more known mitigation(s) on Linux Kernel
  side for the referenced hardware vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the mitigation status reported
  by the Linux Kernel.");

  script_tag(name:"solution", value:"Enable the mitigation(s) in the Linux Kernel or update to a more
  recent Linux Kernel.");

  script_tag(name:"qod", value:"80"); # nb: None of the existing QoD types are matching here
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");

if( ! get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable" ) )
  exit( 99 );

missing_mitigations = get_kb_list( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/list" );
if( missing_mitigations ) {

  cve_mapping = make_array(
    "/sys/devices/system/cpu/vulnerabilities/itlb_multihit",  "(CVE-2018-12207)",
    "/sys/devices/system/cpu/vulnerabilities/l1tf", "(CVE-2018-3615, CVE-2018-3620, CVE-2018-3646)",
    "/sys/devices/system/cpu/vulnerabilities/mds", "(CVE-2018-12126, CVE-2018-12130, CVE-2018-12127, CVE-2019-11091)",
    "/sys/devices/system/cpu/vulnerabilities/meltdown", "(CVE-2017-5754)",
    "/sys/devices/system/cpu/vulnerabilities/spec_store_bypass", "(CVE-2018-3639)",
    "/sys/devices/system/cpu/vulnerabilities/spectre_v1", "(CVE-2017-5753, CVE-2019-1125)",
    "/sys/devices/system/cpu/vulnerabilities/spectre_v2", "(CVE-2017-5715)",
    "/sys/devices/system/cpu/vulnerabilities/tsx_async_abort", "(CVE-2019-11135)" );


  # Sort to not report changes on delta reports if just the order is different
  missing_mitigations = sort( missing_mitigations );
  info = make_array();
  report = 'The Linux Kernel on the remote host is missing one or more mitigation(s) for hardware vulnerabilities as reported by the sysfs interface:\n\n';
  foreach missing_mitigation( missing_mitigations ) {

    split = split( missing_mitigation, sep:"###----###---###", keep:FALSE );
    if( max_index( split ) != 2 )
      continue;

    path   = split[0];
    status = split[1];
    cves = cve_mapping[path];
    if( cves )
      path += " " + cves;
    info[path] = status;
    found = TRUE;
  }

  if( found ) {
    report += text_format_table( array:info, sep:" | ", columnheader:make_list( "sysfs file (Related CVE(s))", "Kernel status" ) );
    report += '\n\nNotes on specific Kernel status output:';
    report += '\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the kernel doesn\'t know this vulnerability yet and is not providing any mitigation which means the target system is vulnerable.';
    report += '\n- Strings including "Mitigation:", "Not affected" or "Vulnerable" are reported directly by the Linux Kernel.';
    report += '\n- All other strings are responses to various SSH commands.';
    security_message( port:0, data:report );
    exit( 0 );
  }
}

exit( 99 );

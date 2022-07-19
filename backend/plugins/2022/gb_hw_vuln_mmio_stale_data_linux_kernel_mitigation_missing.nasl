# Copyright (C) 2022 Greenbone Networks GmbH
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
  script_oid("1.3.6.1.4.1.25623.1.0.104247");
  script_version("2022-07-15T06:04:23+0000");
  script_cve_id("CVE-2022-21123", "CVE-2022-21125", "CVE-2022-21166");
  script_tag(name:"last_modification", value:"2022-07-15 06:04:23 +0000 (Fri, 15 Jul 2022)");
  script_tag(name:"creation_date", value:"2022-07-14 08:04:34 +0000 (Thu, 14 Jul 2022)");
  script_tag(name:"cvss_base", value:"2.1");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-07-07 11:15:00 +0000 (Thu, 07 Jul 2022)");
  script_name("Missing Linux Kernel mitigations for 'Processor MMIO Stale Data' hardware vulnerabilities");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hw_vuln_linux_kernel_mitigation_detect.nasl");
  script_mandatory_keys("ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable");

  script_xref(name:"URL", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/processor_mmio_stale_data.html");

  script_tag(name:"summary", value:"The remote host is missing one or more known mitigation(s) on
  Linux Kernel side for the referenced 'Processor MMIO Stale Data' hardware vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks previous gathered information on the mitigation status
  reported by the Linux Kernel.");

  script_tag(name:"solution", value:"Enable the mitigation(s) in the Linux Kernel or update to a
  more recent Linux Kernel.");

  script_tag(name:"qod", value:"80"); # nb: None of the existing QoD types are matching here
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

include("misc_func.inc");
include("list_array_func.inc");
include("host_details.inc");

if( ! get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable" ) )
  exit( 99 );

covered_vuln = "mmio_stale_data";

mitigation_status = get_kb_item( "ssh/hw_vulns/kernel_mitigations/missing_or_vulnerable/" + covered_vuln );
if( ! mitigation_status )
  exit( 99 );

report = 'The Linux Kernel on the remote host is missing the mitigation for the "' + covered_vuln + '" hardware vulnerabilities as reported by the sysfs interface:\n\n';

path = "/sys/devices/system/cpu/vulnerabilities/" + covered_vuln;
info[path] = mitigation_status;

# Store link between gb_hw_vuln_linux_kernel_mitigation_detect.nasl and this VT.
# nb: We don't use the host_details.inc functions in both so we need to call this directly.
register_host_detail( name:"detected_by", value:"1.3.6.1.4.1.25623.1.0.108765" ); # gb_hw_vuln_linux_kernel_mitigation_detect.nasl
register_host_detail( name:"detected_at", value:"general/tcp" ); # gb_hw_vuln_linux_kernel_mitigation_detect.nasl is using port:0

report += text_format_table( array:info, sep:" | ", columnheader:make_list( "sysfs file checked", "Kernel status (SSH response)" ) );
report += '\n\nNotes on the "Kernel status / SSH response" column:';
report += '\n- sysfs file missing: The sysfs interface is available but the sysfs file for this specific vulnerability is missing. This means the kernel doesn\'t know this vulnerability yet and is not providing any mitigation which means the target system is vulnerable.';
report += '\n- Strings including "Mitigation:", "Not affected" or "Vulnerable" are reported directly by the Linux Kernel.';
report += '\n- All other strings are responses to various SSH commands.';

security_message( port:0, data:report );
exit( 0 );

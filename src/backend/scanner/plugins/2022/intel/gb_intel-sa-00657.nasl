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
  script_oid("1.3.6.1.4.1.25623.1.0.104293");
  script_version("2022-08-12T10:10:36+0000");
  script_cve_id("CVE-2022-21233");
  script_tag(name:"last_modification", value:"2022-08-12 10:10:36 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-11 11:49:08 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:M/C:C/I:N/A:N");
  script_name("Intel CPU Information Disclosure Vulnerability (INTEL-SA-00657, AEPIC)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gather_hardware_info_ssh_login.nasl");
  script_mandatory_keys("ssh/login/intel_cpu/detected");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00657.html");
  script_xref(name:"URL", value:"https://aepicleak.com");
  script_xref(name:"URL", value:"https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files");

  script_tag(name:"summary", value:"The Intel CPU on the remote host might be prone to an
  information disclosure vulnerability dubbed 'AEPIC'.");

  script_tag(name:"vuldetect", value:"Checks if the remote host is using an Intel CPU.");

  script_tag(name:"insight", value:"Improper isolation of shared resources in some Intel(R)
  Processors may allow a privileged user to potentially enable information disclosure via local
  access.");

  script_tag(name:"solution", value:"Intel recommends that users of affected Intel(R) Processors
  update to the latest version firmware provided by the system manufacturer that addresses these
  issues. In addition, Intel will be releasing Intel(R) SGX SDK updates soon after public embargo is
  lifted.

  Intel has released microcode updates for the affected Intel(R) Processors that are currently
  supported on the public github repository. Please see details below on access to the microcode:

  GitHub*: Public Github: [link moved to references]");

  # nb: Just a general note. Mitigation needs to be done via BIOS / microcode updates.
  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

if( ! get_kb_item( "ssh/login/intel_cpu/detected" ) )
  exit( 0 ); # nb: No exit(99); because the system might run on e.g. Windows or similar...

security_message( port:0 );
exit( 0 );

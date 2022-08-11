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
  script_oid("1.3.6.1.4.1.25623.1.0.104263");
  script_version("2022-08-03T08:42:58+0000");
  script_cve_id("CVE-2020-0550");
  script_tag(name:"last_modification", value:"2022-08-03 08:42:58 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-02 14:36:49 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"1.9");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2020-03-24 18:16:00 +0000 (Tue, 24 Mar 2020)");
  script_name("Intel CPU Information Disclosure Vulnerability (INTEL-SA-00330)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gather_hardware_info_ssh_login.nasl");
  script_mandatory_keys("ssh/login/intel_cpu/detected");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00330.html");
  script_xref(name:"URL", value:"https://software.intel.com/security-software-guidance/processors-affected-transient-execution-attack-mitigation-product-cpu-model");
  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/architecture-and-technology/l1tf.html");
  script_xref(name:"URL", value:"https://software.intel.com/security-software-guidance/insights/deep-dive-snoop-assisted-l1-data-sampling");
  script_xref(name:"URL", value:"https://software.intel.com/content/www/us/en/develop/topics/software-security-guidance.html");
  script_xref(name:"URL", value:"https://docs.kernel.org/admin-guide/hw-vuln/l1d_flush.html");

  script_tag(name:"summary", value:"The Intel CPU on the remote host might be prone to an
  information disclosure vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the remote host is using an Intel CPU.");

  script_tag(name:"insight", value:"Improper data forwarding in some data cache for some Intel(R)
  Processors may allow an authenticated user to potentially enable information disclosure via local
  access.");

  script_tag(name:"solution", value:"This potential vulnerability is mitigated by using Virtual
  Machine Manager with the L1TF mitigations applied. For more information see L1TF
  [link moved to references]. Intel is not recommending any new or additional mitigations for
  Operating Systems.

  Additional technical details about this vulnerability can be found at:

  [link moved to references]

  Additional Advisory Guidance on CVE-2020-0550 available here [link moved to references].");

  # nb: Just a general note. Mitigation needs to be done on software side running at this system.
  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( ! get_kb_item( "ssh/login/intel_cpu/detected" ) )
  exit( 0 ); # nb: No exit(99); because the system might run on e.g. Windows or similar...

security_message( port:0 );
exit( 0 );

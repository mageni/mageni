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
  script_oid("1.3.6.1.4.1.25623.1.0.104316");
  script_version("2022-09-07T10:10:59+0000");
  script_cve_id("CVE-2021-33060");
  script_tag(name:"last_modification", value:"2022-09-07 10:10:59 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"creation_date", value:"2022-09-07 06:46:03 +0000 (Wed, 07 Sep 2022)");
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_name("Intel BIOS Privilege Escalation Vulnerability (INTEL-SA-00686)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("Privilege escalation");
  script_dependencies("gb_gather_hardware_info_ssh_login.nasl");
  script_mandatory_keys("ssh/login/intel_cpu/detected");

  script_xref(name:"URL", value:"https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00686.html");

  script_tag(name:"summary", value:"The Intel BIOS on the remote host might be prone to a privilege
  escalation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if the remote host is using an Intel CPU.");

  script_tag(name:"insight", value:"Out-of-bounds write in the BIOS firmware for some Intel(R)
  Processors may allow an authenticated user to potentially enable escalation of privilege via local
  access.");

  script_tag(name:"solution", value:"Intel is releasing BIOS updates to mitigate this potential
  vulnerability.");

  # nb: Just a general note. Mitigation needs to be done by updating the BIOS depending on the
  # hardware / mainboard manufacturer.
  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( ! get_kb_item( "ssh/login/intel_cpu/detected" ) )
  exit( 0 ); # nb: No exit(99); because the system might run on e.g. Windows or similar...

security_message( port:0 );
exit( 0 );

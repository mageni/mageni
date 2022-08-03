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
  script_oid("1.3.6.1.4.1.25623.1.0.104262");
  script_version("2022-08-03T08:42:56+0000");
  script_cve_id("CVE-2022-23823");
  script_tag(name:"last_modification", value:"2022-08-03 08:42:56 +0000 (Wed, 03 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-02 14:36:49 +0000 (Tue, 02 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_tag(name:"severity_vector", value:"CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_tag(name:"severity_origin", value:"NVD");
  script_tag(name:"severity_date", value:"2022-06-29 17:42:00 +0000 (Wed, 29 Jun 2022)");
  script_name("AMD CPU Information Disclosure Vulnerability (AMD-SB-1038, Hertzbleed)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gather_hardware_info_ssh_login.nasl");
  script_mandatory_keys("ssh/login/amd_cpu/detected");

  script_xref(name:"URL", value:"https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1038");
  script_xref(name:"URL", value:"https://link.springer.com/chapter/10.1007/978-3-319-08867-9_8");
  script_xref(name:"URL", value:"https://link.springer.com/chapter/10.1007/978-3-642-38348-9_9");
  script_xref(name:"URL", value:"https://link.springer.com/book/10.1007/978-0-387-38162-6");
  script_xref(name:"URL", value:"https://www.hertzbleed.com");

  script_tag(name:"summary", value:"The AMD CPU on the remote host might be prone to an information
  disclosure vulnerability dubbed 'Hertzbleed'.");

  script_tag(name:"vuldetect", value:"Checks if the remote host is using an AMD CPU.");

  script_tag(name:"insight", value:"A potential vulnerability in some AMD processors using frequency
  scaling may allow an authenticated attacker to execute a timing attack to potentially enable
  information disclosure.");

  script_tag(name:"solution", value:"As the vulnerability impacts a cryptographic algorithm having
  power analysis-based side-channel leakages, developers can apply countermeasures on the software
  code of the algorithm. Either masking, hiding or key-rotation may be used to mitigate the
  attack.");

  # nb: Just a general note. Mitigation needs to be done on software side running at this system.
  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( ! get_kb_item( "ssh/login/amd_cpu/detected" ) )
  exit( 0 ); # nb: No exit(99); because the system might run on e.g. Windows or similar...

security_message( port:0 );
exit( 0 );

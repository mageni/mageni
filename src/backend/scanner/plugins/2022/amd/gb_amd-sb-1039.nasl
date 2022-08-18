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
  script_oid("1.3.6.1.4.1.25623.1.0.104292");
  script_version("2022-08-12T10:10:36+0000");
  script_cve_id("CVE-2021-46778");
  script_tag(name:"last_modification", value:"2022-08-12 10:10:36 +0000 (Fri, 12 Aug 2022)");
  script_tag(name:"creation_date", value:"2022-08-11 11:49:08 +0000 (Thu, 11 Aug 2022)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:P/I:N/A:N");
  script_name("AMD CPU Information Disclosure Vulnerability (AMD-SB-1039, SQUIP)");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2022 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_gather_hardware_info_ssh_login.nasl");
  script_mandatory_keys("ssh/login/amd_cpu/detected");

  script_xref(name:"URL", value:"https://www.amd.com/en/corporate/product-security/bulletin/amd-sb-1039");
  script_xref(name:"URL", value:"https://www.bearssl.org/constanttime.html");
  script_xref(name:"URL", value:"https://www.chosenplaintext.ca/articles/beginners-guide-constant-time-cryptography.html");
  script_xref(name:"URL", value:"https://stefangast.eu/papers/squip.pdf");

  script_tag(name:"summary", value:"The AMD CPU on the remote host might be prone to an information
  disclosure vulnerability dubbed 'SQUIP'.");

  script_tag(name:"vuldetect", value:"Checks if the remote host is using an AMD CPU.");

  script_tag(name:"insight", value:"Execution unit scheduler contention may lead to a side channel
  vulnerability found on AMD CPU microarchitectures codenamed 'Zen 1', 'Zen 2' and 'Zen 3' that use
  simultaneous multithreading (SMT). By measuring the contention level on scheduler queues an
  attacker may potentially leak sensitive information.");

  script_tag(name:"solution", value:"AMD recommends software developers employ existing best
  practices [links moved to references], including constant-time algorithms and avoiding
  secret-dependent control flows where appropriate to help mitigate this potential vulnerability.");

  # nb: Just a general note. Mitigation needs to be done on software side running at this system.
  script_tag(name:"qod_type", value:"general_note");
  script_tag(name:"solution_type", value:"Mitigation");

  exit(0);
}

if( ! get_kb_item( "ssh/login/amd_cpu/detected" ) )
  exit( 0 ); # nb: No exit(99); because the system might run on e.g. Windows or similar...

security_message( port:0 );
exit( 0 );

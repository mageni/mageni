###############################################################################
# OpenVAS Vulnerability Test
#
# OpenSSH Multiple Vulnerabilities Jan17 (Linux)
#
# Authors:
# Tushar Khelge <ktushar@secpod.com>
#
# Copyright:
# Copyright (C) 2017 Greenbone Networks GmbH, http://www.greenbone.net
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = "cpe:/a:openbsd:openssh";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.8103256");
  script_version("2019-05-21T12:48:06+0000");
  script_cve_id("CVE-2016-10009", "CVE-2016-10010", "CVE-2016-10011", "CVE-2016-10012", "CVE-2016-10708");
  script_bugtraq_id(94968, 94972, 94977, 94975);
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"last_modification", value:"2019-05-21 12:48:06 +0000 (Tue, 21 May 2019)");
  script_tag(name:"creation_date", value:"2017-01-06 11:19:51 +0530 (Fri, 06 Jan 2017)");
  script_name("OpenSSH Multiple Vulnerabilities Jan17 (Linux)");
  script_copyright("Copyright (C) 2017 Greenbone Networks GmbH");
  script_category(ACT_GATHER_INFO);
  script_family("General");
  script_dependencies("gb_openssh_consolidation.nasl", "os_detection.nasl");
  script_mandatory_keys("openssh/detected", "Host/runs_unixoide");

  script_xref(name:"URL", value:"https://www.openssh.com/txt/release-7.4");
  script_xref(name:"URL", value:"http://www.openwall.com/lists/oss-security/2016/12/19/2");
  script_xref(name:"URL", value:"http://blog.swiecki.net/2018/01/fuzzing-tcp-servers.html");
  script_xref(name:"URL", value:"https://anongit.mindrot.org/openssh.git/commit/?id=28652bca29046f62c7045e933e6b931de1d16737");

  script_tag(name:"summary", value:"This host is installed with openssh and
  is prone to multiple vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"insight", value:"Multiple flaws exists due to,

  - An 'authfile.c' script does not properly consider the effects of realloc
    on buffer contents.

  - The shared memory manager (associated with pre-authentication compression)
    does not ensure that a bounds check is enforced by all compilers.

  - The sshd in OpenSSH creates forwarded Unix-domain sockets as root, when
    privilege separation is not used.

  - An untrusted search path vulnerability in ssh-agent.c in ssh-agent.

  - NULL pointer dereference error due to an out-of-sequence NEWKEYS message.");

  script_tag(name:"impact", value:"Successfully exploiting this issue allows
  local users to obtain sensitive private-key information, to gain privileges,
  conduct a senial-of-service condition and allows remote attackers to execute
  arbitrary local PKCS#11 modules.");

  script_tag(name:"affected", value:"OpenSSH versions before 7.4 on Linux");

  script_tag(name:"solution", value:"Upgrade to OpenSSH version 7.4 or later.");

  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner_unreliable");

  exit(0);
}

include("version_func.inc");
include("host_details.inc");

if(isnull(port = get_app_port(cpe:CPE)))
  exit(0);

if(!infos = get_app_version_and_location(cpe:CPE, port:port, exit_no_version:TRUE))
  exit(0);

vers = infos["version"];
path = infos["location"];

if(version_is_less(version:vers, test_version:"7.4")) {
  report = report_fixed_ver(installed_version:vers, fixed_version:"7.4", install_path:path);
  security_message(port:port, data:report);
  exit(0);
}

exit(99);
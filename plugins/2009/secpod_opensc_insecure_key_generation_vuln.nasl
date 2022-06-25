###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_opensc_insecure_key_generation_vuln.nasl 13273 2019-01-24 15:12:48Z asteins $
#
# OpenSC < 0.11.8 Incorrect RSA Keys Generation Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900639");
  script_version("$Revision: 13273 $");
  script_tag(name:"last_modification", value:"$Date: 2019-01-24 16:12:48 +0100 (Thu, 24 Jan 2019) $");
  script_tag(name:"creation_date", value:"2009-05-20 10:26:22 +0200 (Wed, 20 May 2009)");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-1603");
  script_bugtraq_id(34884);
  script_name("OpenSC < 0.11.8 Incorrect RSA Keys Generation Vulnerability");
  script_xref(name:"URL", value:"http://secunia.com/advisories/35035");
  script_xref(name:"URL", value:"http://www.vupen.com/english/advisories/2009/1295");
  script_xref(name:"URL", value:"http://www.opensc-project.org/pipermail/opensc-announce/2009-May/000025.html");

  script_tag(name:"qod_type", value:"executable_version_unreliable");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Privilege escalation");
  script_dependencies("gb_opensc_detect.nasl");
  script_mandatory_keys("opensc/detected");

  script_tag(name:"impact", value:"Successful exploitation will allow attacker to obtain the sensitive
  information or gain unauthorized access to the smartcard.");

  script_tag(name:"affected", value:"OpenSC version prior to 0.11.8 on Linux.");

  script_tag(name:"insight", value:"Security issues are due to,

  - a tool that starts a key generation with public exponent set to 1, an
    invalid value that causes an insecure RSA key.

  - a PKCS#11 module that accepts that this public exponent and forwards it
    to the card.

  - a card that accepts the public exponent and generates the rsa key.");

  script_tag(name:"solution", value:"Upgrade to OpenSC version 0.11.8 or later.");

  script_tag(name:"summary", value:"This host is installed with OpenSC and is prone to an insecure key
  generation vulnerability.");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  script_tag(name:"solution_type", value:"VendorFix");

  exit(0);
}

CPE = "cpe:/a:opensc-project:opensc";

include("host_details.inc");
include("version_func.inc");

if(!infos = get_app_version_and_location(cpe: CPE, exit_no_version: TRUE))
  exit(0);

vers = infos['version'];
path = infos['location'];

if(version_is_less(version: vers, test_version: "0.11.8")) {
  report = report_fixed_ver(installed_version: vers, fixed_version: "0.11.8", install_path: path);
  security_message(port: 0, data: report);
  exit(0);
}

exit(99);


###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_westermo_weos_certificate_vuln.nasl 12096 2018-10-25 12:26:02Z asteins $
#
# Westermo WeOS Hard-coded Certificate Vulnerability
#
# Authors:
# Christian Kuersteiner <christian.kuersteiner@greenbone.net>
#
# Copyright:
# Copyright (c) 2016 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

CPE = 'cpe:/o:westermo:weos';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106197");
  script_version("$Revision: 12096 $");
  script_tag(name:"last_modification", value:"$Date: 2018-10-25 14:26:02 +0200 (Thu, 25 Oct 2018) $");
  script_tag(name:"creation_date", value:"2016-08-24 11:49:27 +0700 (Wed, 24 Aug 2016)");
  script_tag(name:"cvss_base", value:"9.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_cve_id("CVE-2015-7923");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name:"solution_type", value:"VendorFix");

  script_name("Westermo WeOS Hard-coded Certificate Vulnerability");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_westermo_weos_detect.nasl");
  script_mandatory_keys("westermo_weos/detected");

  script_tag(name:"summary", value:"Westermo WeOS uses the same SSL private key across different customers
installations.");

  script_tag(name:"insight", value:"The SSL keys used by the switches to provide secure communications are
hard coded. Malicious parties could obtain the key, stage a Man-in-the-Middle attack posing to be a WeOS device,
and then obtain credentials entered by the end-user. With those credentials, the malicious party would have
authenticated access to that device.");

  script_tag(name:"impact", value:"Certificates provide a key used by the switch software to encrypt and
decrypt communications. The detrimental impact of the certificate being hard coded is that the key cannot be
changed. Once the key is compromised, a malicious party has access to the decrypted network traffic from the
device. A malicious party can then read and modify traffic that is intercepted and decrypted.");

  script_tag(name:"affected", value:"WeOS versions older than Version 4.19.0");

  script_tag(name:"solution", value:"Westermo has released a patch that allows changing default certificates
to custom certificates.");

  script_xref(name:"URL", value:"https://ics-cert.us-cert.gov/advisories/ICSA-16-028-01");

  script_tag(name:"vuldetect", value:"Checks if a vulnerable version is present on the target host.");

  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

if (version_is_less(version: version ,test_version: "4.19.0")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "Contact the vendor.");
  security_message(port: 0, data: report);
  exit(0);
}

exit(0);

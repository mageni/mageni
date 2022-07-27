##############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_hp_comware_platform_hpsbhf03673.nasl 11640 2018-09-27 07:15:20Z asteins $
#
# HPE Network Products Multiple Remote Vulnerabilities
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

CPE = 'cpe:/a:hp:comware';

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.106412");
  script_version("$Revision: 11640 $");
  script_tag(name:"last_modification", value:"$Date: 2018-09-27 09:15:20 +0200 (Thu, 27 Sep 2018) $");
  script_tag(name:"creation_date", value:"2016-11-25 13:11:53 +0700 (Fri, 25 Nov 2016)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:P/A:N");

  script_cve_id("CVE-2004-2761", "CVE-2013-2566", "CVE-2015-2808");

  script_tag(name:"qod_type", value:"remote_active");

  script_tag(name:"solution_type", value:"Mitigation");

  script_name("HPE Network Products Multiple Remote Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("This script is Copyright (C) 2016 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gb_hp_comware_platform_detect_snmp.nasl", "gb_hp_comware_platform_detect_ssh.nasl",
"secpod_ssl_ciphers.nasl");
  script_mandatory_keys("hp/comware_device", "secpod_ssl_ciphers/supported_ciphers", "ssl_tls/port");

  script_tag(name:"summary", value:"HPE Comware 5 and Comware 7 network products are prone to multiple
vulnerabilities.");

  script_tag(name:"vuldetect", value:"Checks if RC2 and RC4 ciphers are enabled on the SSL ports.");

  script_tag(name:"insight", value:"Security vulnerabilities in MD5 message digest algorithm and RC4
ciphersuite could potentially impact HPE Comware 5 and Comware 7 network products using SSL/TLS. These
vulnerabilities could be exploited remotely to conduct spoofing attacks and plaintext recovery attacks resulting
in disclosure of information.");

  script_tag(name:"impact", value:"An attacker may conduct spoofing and plaintext recovery attacks resulting
in information disclosure.");

  script_tag(name:"affected", value:"Comware 5 and Comware 7 Products: All versions");

  script_tag(name:"solution", value:"For mitigation HPE recommends disabling RC2 and RC4 ciphers.");

  script_xref(name:"URL", value:"https://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c05336888");

  exit(0);
}

include("host_details.inc");
include("ssl_funcs.inc");

if (!version = get_app_version(cpe: CPE, nofork: TRUE))
  exit(0);

if (version =~ "^(5|7)") {
  port = get_ssl_port();
  if (!port)
    exit(0);

  weakciphers = get_kb_list("secpod_ssl_ciphers/*/" + port + "/supported_ciphers");
  if (weakciphers =~ "(_RC4_)|(_RC2_)") {
    security_message(port: port);
    exit(0);
  }
}

exit(0);
